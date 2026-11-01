-- LSASS memory dump through comsvcs.dll MiniDump
-- 5c090911-d1d5-4467-ad27-f385bf5a7156
SELECT uid, time, hostname, product, user_name, process_name, process_path, cmd_line, parent_path, target_file, dst_ip, dst_port FROM ocsf_flat WHERE time >= ? AND time < ? AND class_uid = 1007 AND activity_id = 1 AND (coalesce(cmd_line ILIKE '%comsvcs%' ESCAPE '\', false) AND coalesce(cmd_line ILIKE '%minidump%' ESCAPE '\', false)) ORDER BY time;
