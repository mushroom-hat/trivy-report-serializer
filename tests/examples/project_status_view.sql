--- Get total number of green, amber, red and justified CVEs for all projects
WITH latest_project_status AS (
        SELECT DISTINCT ON (ps.project_id) ps.project_id,
          ps.status,
          ps.calculated_at
          FROM project_status ps
        ORDER BY ps.project_id, ps.calculated_at DESC
      )
SELECT p.id AS project_id,
  p.team,
  p.project AS project_name,
  lps.status AS project_status,
  lps.calculated_at AS status_calculated_at,
  COALESCE(sum(
      CASE
          WHEN (cf.severity::text = ANY (ARRAY['critical'::character varying, 'high'::character varying]::text[])) AND cf.justified = false AND (cf.last_seen_at::date - cf.published_at::date) < 30 THEN 1
          ELSE 0
      END), 0::bigint) AS green_cves,
  COALESCE(sum(
      CASE
          WHEN (cf.severity::text = ANY (ARRAY['critical'::character varying, 'high'::character varying]::text[])) AND cf.justified = false AND (cf.last_seen_at::date - cf.published_at::date) >= 30 AND (cf.last_seen_at::date - cf.published_at::date) <= 89 THEN 1
          ELSE 0
      END), 0::bigint) AS amber_cves,
  COALESCE(sum(
      CASE
          WHEN (cf.severity::text = ANY (ARRAY['critical'::character varying, 'high'::character varying]::text[])) AND cf.justified = false AND (cf.last_seen_at::date - cf.published_at::date) >= 90 THEN 1
          ELSE 0
      END), 0::bigint) AS red_cves,
  COALESCE(sum(
      CASE
          WHEN (cf.severity::text = ANY (ARRAY['critical'::character varying, 'high'::character varying]::text[])) AND cf.justified = true THEN 1
          ELSE 0
      END), 0::bigint) AS justified_cves
  FROM projects p
    LEFT JOIN images i ON i.project_id = p.id
    LEFT JOIN cve_findings cf ON cf.image_id = i.id
    LEFT JOIN latest_project_status lps ON lps.project_id = p.id
GROUP BY p.id, p.team, p.project, lps.status, lps.calculated_at
ORDER BY p.project;