
-- Get all images used for project
SELECT
  i.*
FROM images i
JOIN projects p ON i.project_id = p.id
WHERE p.project = 'ocp-release';

-- Get all CVEs for a particular image
SELECT * FROM cve_findings cf
JOIN images i
  ON cf.image_id = i.id
JOIN projects p
  ON i.project_id = p.id
WHERE i.path = 'velero/velero'
  AND i.tag  = 'v1.17.1'
ORDER BY cf.severity DESC, cf.score DESC;


--
UPDATE cve_findings
SET justified = true
WHERE id in (323,324,325,326,327,328,330,337,339,347,354,355,360,361,362,363);
SELECT * FROM public.project_cve_findings_view WHERE project = 'ocp-release';