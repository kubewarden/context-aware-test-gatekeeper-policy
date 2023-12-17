package policy

violation[{"msg": msg}] {
	input.review.object.kind == "Deployment"
    input.review.object.metadata.labels["app.kubernetes.io/component"] == "api"
    not input.review.object.metadata.labels["customer-id"]

	msg := "Label customer-id is required for API deployments"
}

violation[{"msg": msg}] {
    namespace := input.review.namespace
    customer_id := input.review.object.metadata.labels["customer-id"]
    not data.inventory.cluster.v1.Namespace[namespace].metadata.labels["customer-id"] == customer_id

	msg := "Deployment must be created in the matching customer namespace"
}

violation[{"msg": msg}] {
    has_database := { i | data.inventory.namespace["customer-1"]["apps/v1"].Deployment[i].metadata.labels["app.kubernetes.io/component"] == "database" }
    not count(has_database) > 0
    
    msg := "No database component found"
}

violation[{"msg": msg}] {
    has_frontend := { i | data.inventory.namespace["customer-1"]["apps/v1"].Deployment[i].metadata.labels["app.kubernetes.io/component"] == "frontend" }
    not count(has_frontend) > 0
    
    msg := "No frontend component found"
}

violation[{"msg": msg}] {
    not data.inventory.namespace["customer-1"].v1.Service["api-auth-service"].metadata.labels["app.kubernetes.io/part-of"] == "api"
    
    msg := "No API authentication service found"
}
