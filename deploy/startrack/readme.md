helm upgrade --install startrack ./deploy/startrack/ -n trivy-system -f ./deploy/startrack/values.yaml
helm upgrade --install postgresql bitnami/postgresql -n trivy-system -f ./deploy/postgres/values-openshift.yaml
helm upgrade --install trivy-operator aqua/trivy-operator --namespace trivy-system --version 0.31.0 -f ./deploy/trivy-operator/values.yaml
oc apply -n trivy-system -f ./deploy/startrack/secrets.yaml

oc cp trivy_schema.sql startrack/postgresql-0:/tmp
psql -f trivy_schema.sql -U postgres -d postgres

helm upgrade --install pgadmin4 runix/pgadmin4 -n trivy-system
