variable "gke_location" {
  type    = string
  default = "europe-west6" # zurich is low carbon
}

variable "project_id" {
  type = string
}

resource "google_container_cluster" "shack_cluster" {
  project  = var.project_id
  name     = "shack-cluster"
  location = var.gke_location

  min_master_version = "1.24"

  initial_node_count       = 1
  remove_default_node_pool = true

  enable_shielded_nodes = false

  description = "GKE cluster for testing shack"

  monitoring_service = "monitoring.googleapis.com/kubernetes"
  logging_service    = "logging.googleapis.com/kubernetes"

  release_channel {
    channel = "RAPID"
  }

  maintenance_policy {
    daily_maintenance_window {
      start_time = "06:00"
    }
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  enable_legacy_abac = false

  addons_config {
    http_load_balancing {
      disabled = true
    }

    horizontal_pod_autoscaling {
      disabled = false
    }
  }

  lifecycle {
    #prevent_destroy = "true"
  }
}

resource "google_container_node_pool" "shack_nodepool" {
  count = 1
  name  = "shack-containerd-pool"

  project            = var.project_id
  location           = var.gke_location
  cluster            = google_container_cluster.shack_cluster.name
  initial_node_count = 1

  autoscaling {
    min_node_count = 1
    max_node_count = 2
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = "e2-standard-2"

    disk_size_gb = "35"
    disk_type    = "pd-ssd"

    image_type = "COS_CONTAINERD"

    metadata = {
      "disable-legacy-endpoints" = "true"
      serial-port-enable         = true
    }

    preemptible = true

    oauth_scopes = [
      "storage-ro",
      "logging-write",
      "monitoring",
    ]
  }
}

