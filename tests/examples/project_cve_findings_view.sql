CREATE OR REPLACE VIEW project_cve_findings_view AS
SELECT
  cf.id        AS cve_finding_id,
  p.project,
  i.path AS image_path,
  i.tag AS image_tag,
  cf.cve_id,
  cf.package_name,
  cf.severity,
  cf.justified
FROM cve_findings cf
JOIN images i
  ON cf.image_id = i.id
JOIN projects p
  ON i.project_id = p.id
WHERE cf.severity IN ('critical', 'high');
