CREATE OR REPLACE FUNCTION recompute_project_status_on_justification_change()
RETURNS trigger AS
$$
DECLARE
    v_project_id     INTEGER;
    v_new_status     TEXT := 'green';
    v_latest_status  TEXT;
BEGIN
    -- Only run when justification actually changes
    IF NEW.justified IS NOT DISTINCT FROM OLD.justified THEN
        RETURN NEW;
    END IF;

    -- Get project_id via image
    SELECT i.project_id
    INTO v_project_id
    FROM images i
    WHERE i.id = NEW.image_id;

    -- Compute worst-case status across all *non-justified* CVEs
    SELECT
        CASE
            WHEN MAX(
                CASE
                    WHEN (cf.last_seen_at - cf.published_at) >= INTERVAL '90 days' THEN 3
                    WHEN (cf.last_seen_at - cf.published_at) >= INTERVAL '30 days' THEN 2
                    ELSE 1
                END
            ) = 3 THEN 'red'
            WHEN MAX(
                CASE
                    WHEN (cf.last_seen_at - cf.published_at) >= INTERVAL '30 days' THEN 2
                    ELSE 1
                END
            ) = 2 THEN 'amber'
            ELSE 'green'
        END
    INTO v_new_status
    FROM cve_findings cf
    JOIN images i ON i.id = cf.image_id
    WHERE i.project_id = v_project_id
      AND cf.justified = FALSE
      AND cf.severity IN ('critical', 'high');
    -- Fetch latest stored project status
    SELECT ps.status
    INTO v_latest_status
    FROM project_status ps
    WHERE ps.project_id = v_project_id
    ORDER BY ps.calculated_at DESC
    LIMIT 1;

    -- Insert only if status changed (or no previous status)
    IF v_latest_status IS DISTINCT FROM v_new_status THEN
        INSERT INTO project_status (
            project_id,
            status,
            calculated_at
        )
        VALUES (
            v_project_id,
            v_new_status,
            NOW()
        );
    END IF;
    RETURN NEW;
    
END;
$$ LANGUAGE plpgsql;

---
CREATE TRIGGER trg_recompute_project_status_on_justification
AFTER UPDATE OF justified
ON cve_findings
FOR EACH ROW
EXECUTE FUNCTION recompute_project_status_on_justification_change();
