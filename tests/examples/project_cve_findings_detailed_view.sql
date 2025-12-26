-- # Get all CVE findings along with their associated images and project information
SELECT
  cf.id               AS cve_finding_id,
  cf.cve_id,
  cf.severity,
  cf.score,
  cf.package_name,
  cf.installed_ver,
  cf.fixed_ver,
  cf.first_seen_at,
  cf.last_seen_at,
  cf.due_at,
  cf.justified,

  i.id                AS image_id,
  i.path              AS image_path,
  i.tag               AS image_tag,
  i.digest,
  i.namespace,
  i.env,
  i.site,

  p.id                AS project_id,
  p.team,
  p.project           AS project_name

FROM cve_findings cf
JOIN images i
  ON cf.image_id = i.id
JOIN projects p
  ON i.project_id = p.id
ORDER BY
  p.project,
  i.path,
  cf.severity DESC,
  cf.score DESC;
