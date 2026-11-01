-- Crontab replaced from a file
-- 49fbd086-a1bf-4f2e-bc1d-07557ee4129a
SELECT uid, time, hostname, product, user_name, process_name, process_path, cmd_line, parent_path, target_file, dst_ip, dst_port FROM ocsf_flat WHERE time >= ? AND time < ? AND class_uid = 1007 AND activity_id = 1 AND (coalesce(process_path ILIKE '%/crontab' ESCAPE '\', false) AND coalesce(regexp_matches(cmd_line, 'crontab\s+(-u\s+\S+\s+)?[^-\s]\S*\s*$'), false)) ORDER BY time;
