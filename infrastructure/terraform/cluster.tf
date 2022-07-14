variable "gke_location" {
  type    = string
  default = "europe-west6" # zurich is low carbon
}

variable "project_id" {
  type = string
}

resource "google_service_account" "shack_sa" {
  project = var.project_id
  account_id   = "shack-cluster-sa"
  display_name = "Shack Cluster SA"
}

resource "google_container_cluster" "shack_cluster" {
  project = var.project_id

  name     = "shack-cluster"
  location = var.gke_location

  min_master_version = "1.24"

  initial_node_count       = 1
  remove_default_node_pool = true

  enable_shielded_nodes = false

  description = "GKE cluster for testing shack"

  release_channel {
    channel = "RAPID"
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
    machine_type = "e2-medium"

    disk_size_gb = "35"
    disk_type    = "pd-ssd"

    image_type = "COS_CONTAINERD"

    preemptible = true

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.shack_sa.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
