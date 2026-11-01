-- Local account created with useradd or adduser
-- 2a7fe49d-58cf-448a-b8e9-e31ad799015d
SELECT uid, time, hostname, product, user_name, process_name, process_path, cmd_line, parent_path, target_file, dst_ip, dst_port FROM ocsf_flat WHERE time >= ? AND time < ? AND class_uid = 1007 AND activity_id = 1 AND (coalesce(process_path ILIKE '%/useradd' ESCAPE '\', false) OR coalesce(process_path ILIKE '%/adduser' ESCAPE '\', false)) ORDER BY time;
