"""pySigma: an OCSF processing pipeline and a DuckDB backend for the Watchfloor lake.

Rules are ordinary Sigma rules with the usual field names (``Image``, ``CommandLine``, ``TargetFilename``...). The
pipeline maps those names onto columns of the ``ocsf_flat`` view (see :mod:`detection_rules.lake`), which projects
OCSF 1.4.0 documents from the Parquet lake. The backend turns each rule into one parameterised SELECT:

    SELECT ... FROM ocsf_flat WHERE time >= ? AND time < ? AND <logsource class filter> AND (<detection>)

String matching is case-insensitive (Sigma's default) with ``ILIKE ... ESCAPE '\\'``; ``|cased`` uses ``LIKE``;
``|re`` uses RE2 through ``regexp_matches``. Values never reach SQL unescaped: quotes are doubled, LIKE
metacharacters escaped, and the time bounds are bind parameters.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from sigma.conditions import ConditionAND, ConditionItem, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.conditions import ExcludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import DetectionItemFailureTransformation, FieldMappingTransformation
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaString

# Sigma field -> ocsf_flat column. Keep in step with lake.FLAT_VIEW.
FIELD_MAP: dict[str, str] = {
    "Image": "process_path",
    "CommandLine": "cmd_line",
    "ProcessId": "process_pid",
    "ParentImage": "parent_path",
    "ParentCommandLine": "parent_cmd_line",
    "ParentProcessId": "parent_pid",
    "User": "user_name",
    "TargetFilename": "target_file",
    "SourceIp": "src_ip",
    "SourcePort": "src_port",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "Computer": "hostname",
}

# Sigma logsource category -> OCSF class/activity filter.
CATEGORY_FILTER: dict[str, str] = {
    "process_creation": "class_uid = 1007 AND activity_id = 1",
    "file_access": "class_uid = 1001 AND activity_id = 2",
    "file_event": "class_uid = 1001 AND activity_id IN (1, 3)",
    "file_delete": "class_uid = 1001 AND activity_id = 4",
    "network_connection": "class_uid = 4001",
}

RESULT_COLUMNS = ("uid", "time", "hostname", "product", "user_name", "process_name", "process_path", "cmd_line",
                  "parent_path", "target_file", "dst_ip", "dst_port")


def ocsf_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Sigma to Watchfloor OCSF 1.4.0",
        priority=20,
        allowed_backends=frozenset({"duckdb"}),
        items=[
            ProcessingItem(identifier="ocsf_field_mapping", transformation=FieldMappingTransformation(FIELD_MAP)),
            ProcessingItem(
                identifier="ocsf_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "this field has no OCSF mapping in the Watchfloor pipeline"),
                field_name_conditions=[ExcludeFieldCondition(fields=list(FIELD_MAP.values()))],
            ),
        ],
    )


class DuckDBBackend(TextQueryBackend):
    """Sigma -> DuckDB SQL over the Watchfloor OCSF lake."""

    name: ClassVar[str] = "Watchfloor DuckDB"
    identifier: ClassVar[str] = "duckdb"
    formats: ClassVar[dict[str, str]] = {"default": "parameterised DuckDB SELECT"}
    requires_pipeline: ClassVar[bool] = False
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ocsf_pipeline()

    precedence: ClassVar[tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]] = (
        ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = " = "

    field_quote: ClassVar[str | None] = None
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "%"
    wildcard_single: ClassVar[str] = "_"
    add_escaped: ClassVar[str] = "%_"
    str_quote: ClassVar[str] = "'"

    # Every comparison is wrapped in coalesce(..., false): a field the event does not have is "no match", so that
    # "not filter" still matches events without that field (SQL's NULL would silently drop them).
    eq_expression: ClassVar[str] = "coalesce({field} ILIKE {value} ESCAPE '\\', false)"
    wildcard_match_expression: ClassVar[str] = "coalesce({field} ILIKE {value} ESCAPE '\\', false)"
    case_sensitive_match_expression: ClassVar[str] = "coalesce({field} LIKE {value} ESCAPE '\\', false)"

    re_expression: ClassVar[str] = "coalesce(regexp_matches({field}, '{regex}'), false)"
    re_escape_char: ClassVar[str] = "'"
    re_escape: ClassVar[tuple[str, ...]] = ("'",)
    re_escape_escape_char: bool = False
    re_flag_prefix: bool = True

    compare_op_expression: ClassVar[str] = "coalesce({field} {operator} {value}, false)"
    compare_operators: ClassVar[dict[Any, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }
    field_null_expression: ClassVar[str] = "{field} IS NULL"
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"
    field_in_list_expression: ClassVar[str | None] = None  # IN is case-sensitive; ORs of ILIKE are not

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """A single-quoted LIKE pattern: wildcards become % and _, literal %, _ and \\ are escaped, ' is doubled."""
        pattern = s.convert(escape_char="\\", wildcard_multi="%", wildcard_single="_", add_escaped="%_\\")
        return "'" + pattern.replace("'", "''") + "'"

    def convert_condition_field_eq_val_num(self, cond: Any, state: ConversionState) -> str:
        return f"coalesce({self.escape_and_quote_field(cond.field)} = {int(cond.value.number)}, false)"

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        category = rule.logsource.category
        if category not in CATEGORY_FILTER:
            raise SigmaFeatureNotSupportedByBackendError(
                f"logsource category {category!r} has no OCSF class mapping "
                f"(supported: {', '.join(sorted(CATEGORY_FILTER))})", source=rule.source)
        cols = ", ".join(RESULT_COLUMNS)
        return (f"SELECT {cols} FROM ocsf_flat WHERE time >= ? AND time < ? AND {CATEGORY_FILTER[category]} "  # noqa: S608
                f"AND ({query}) ORDER BY time")


_WS = re.compile(r"\s+")


def pretty(sql: str) -> str:
    """Collapse whitespace so stored queries diff cleanly."""
    return _WS.sub(" ", sql).strip()
