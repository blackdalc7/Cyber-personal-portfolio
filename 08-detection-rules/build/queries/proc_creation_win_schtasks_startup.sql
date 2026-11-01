-- Scheduled task created to run at startup or logon
-- 7d754821-6c6f-4f0a-9b25-951710fca9d9
SELECT uid, time, hostname, product, user_name, process_name, process_path, cmd_line, parent_path, target_file, dst_ip, dst_port FROM ocsf_flat WHERE time >= ? AND time < ? AND class_uid = 1007 AND activity_id = 1 AND (coalesce(process_path ILIKE '%\\schtasks.exe' ESCAPE '\', false) AND coalesce(cmd_line ILIKE '%/create%' ESCAPE '\', false) AND (coalesce(cmd_line ILIKE '%onstart%' ESCAPE '\', false) OR coalesce(cmd_line ILIKE '%onlogon%' ESCAPE '\', false))) ORDER BY time;
