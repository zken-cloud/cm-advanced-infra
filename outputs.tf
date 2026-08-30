output "ssh" {
  description = "How to get in. There is no external IP; --tunnel-through-iap is not optional."
  value       = "gcloud compute ssh ${google_compute_instance.lab.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap"
}

output "bootstrap_status" {
  description = "Run this on the VM. The bootstrap takes ~20 min; this says where it is."
  value       = "cm-lab-status"
}

output "lab_repo" {
  value = github_repository.lab.html_url
}

output "wif_provider" {
  value = google_iam_workload_identity_pool_provider.github.name
}

output "next" {
  value = <<-EOT

    1. Wait for the bootstrap, then SSH in:
         gcloud compute ssh ${google_compute_instance.lab.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap
    2. Check it finished:
         cm-lab-status
    3. Start the lab at Step 1:
         cd ~/cm-lab && semgrep scan --config=p/javascript --config=p/nodejs --json -o semgrep.json .
  EOT
}
