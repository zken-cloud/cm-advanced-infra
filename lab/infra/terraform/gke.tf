# Autopilot: no node pools to size, no idle node cost; pods bill per requested
# resource while running. gVisor is available as `runtimeClassName: gvisor`,
# which is what contains CodeMender -- its own --sandbox cannot run here
# (see docs/cm-exebox-gvisor-clash.md), so the Jobs pass --sandbox=false.
#
# No spot node pool, by decision: a preempted verify pod burns its agent-minutes
# and returns no verdict.
# THE CONTROL PLANE IS PUBLIC, DELIBERATELY, AND ONLY FOR THE LAB.
#
# There is no `private_cluster_config` and no `master_authorized_networks_config`,
# so the API server accepts connections from anywhere that holds a credential. That
# is a lab-scope decision, taken 2026-08-25 with the exposure understood -- see
# README "Before you run this in production". It is load-bearing here: the Cloud Run
# reconciler creates verify Jobs, and it reaches the API server over that public
# endpoint. Locking the endpoint down without also giving the reconciler a private
# path breaks the pipeline, so the two changes are one change.
#
# In production, do BOTH of these, not either:
#   master_authorized_networks_config { cidr_blocks { ... } }   # who may connect
#   private_cluster_config { enable_private_endpoint = true }   # no public endpoint
# and give the reconciler Direct VPC egress so it is inside that boundary.
# Authentication is not the control here -- IAM already gates who may act. The
# control is reachability: an unauthenticated attacker still gets to talk to the
# API server, which is a much larger attack surface than they need to be offered.
# AN EXPLICIT NETWORK, not the auto-created `default`.
#
# Found by applying this config to an empty project (2026-08-25): GKE failed with
# `Project "..." has no network named "default"`, and the two Workload Identity
# bindings failed behind it because the WI pool only exists once a cluster does. The
# stack had never been provisioned from clean -- it converged against a project that
# already had a default network, so the dependency was invisible.
#
# Creating one is also the better answer regardless of greenfield: the auto-created
# default network ships permissive firewall rules and exists in every region, which
# is more surface than a lab -- or a production estate -- has any reason to offer.
resource "google_compute_network" "vpc" {
  name                    = "${var.name_prefix}-net"
  auto_create_subnetworks = false
  depends_on              = [time_sleep.services_ready]
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.name_prefix}-subnet"
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = "10.24.0.0/20"
  # Autopilot needs secondary ranges for pods and services. Sized for the 100-pod
  # verify cap with room to spare; both are private and never routed outward.
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.28.0.0/14"
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.32.0.0/20"
  }
  private_ip_google_access = true
}

# EGRESS FOR PRIVATE NODES. With no external IPs the nodes still need to reach
# github.com to clone the target; Google APIs are covered by private Google access
# on the subnet, but GitHub is not. Cloud NAT is that path.
#
# It is also the seam where egress becomes restrictable at all: with external IPs on
# every node there is no single place to put a policy. This does not yet restrict
# anything -- see README "Before you run this in production" -- but it is the
# prerequisite for doing so.
resource "google_compute_router" "router" {
  name    = "${var.name_prefix}-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.name_prefix}-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_container_cluster" "cluster" {
  name             = var.name_prefix
  location         = var.region
  enable_autopilot = true
  network          = google_compute_network.vpc.id
  subnetwork       = google_compute_subnetwork.subnet.id

  # PRIVATE NODES, PUBLIC CONTROL PLANE. Nodes get no external IPs -- required here
  # by the org policy constraints/compute.vmExternalIpAccess, which failed the
  # greenfield apply, and correct anyway: a pod executing synthesised exploit code
  # has no business holding a public address.
  #
  # enable_private_endpoint stays FALSE by decision: the control plane is reachable
  # from the internet so the Cloud Run reconciler can create verify Jobs. That is
  # the lab's accepted exposure, and the README says what production must do
  # instead. Private NODES and a private ENDPOINT are separate switches; this is the
  # first one only.
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
  }
  depends_on = [google_compute_router_nat.nat, time_sleep.services_ready]
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
  release_channel { channel = var.cluster_release_channel }
  deletion_protection = false
  # WIF is on by default in Autopilot (workload_identity_config = project.svc.id.goog)
}
