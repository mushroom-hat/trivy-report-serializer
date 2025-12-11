WITH latest_images AS (
    SELECT DISTINCT ON (i.project_id, i.namespace, i.env, i.cluster, i.registry, i.path)
        i.id AS image_id,
        i.project_id,
        i.namespace,
        i.env,
        i.cluster,
        i.registry,
        i.path
    FROM images i
    WHERE i.namespace = 'lj'
      AND i.env = 'prd'
      AND i.cluster = 'site_1'
    ORDER BY i.project_id, i.namespace, i.env, i.cluster, i.registry, i.path, i.created_at DESC
),

classified_findings AS (
    SELECT
        f.*,
        p.project AS project_name,
        CASE
            WHEN EXTRACT(EPOCH FROM (f.last_seen_at - f.published_at)) / 86400 BETWEEN 30 AND 60
                THEN 'Low'
            WHEN EXTRACT(EPOCH FROM (f.last_seen_at - f.published_at)) / 86400 < 90
                THEN 'Medium'
            ELSE 'High'
        END AS status
    FROM cve_findings f
    JOIN latest_images li ON li.image_id = f.image_id
    JOIN projects p ON p.id = li.project_id
)

SELECT
    project_name,
    status,
    COUNT(*) AS total_cves
FROM classified_findings
GROUP BY project_name, status
ORDER BY project_name, status;
