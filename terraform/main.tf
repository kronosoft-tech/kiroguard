terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─── AMI Lookup ─────────────────────────────────────────────────────────────

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ─── VPC & Public Subnet ────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-subnet" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.project_name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ─── Security Group ─────────────────────────────────────────────────────────

resource "aws_security_group" "kiroguard" {
  name        = "${var.project_name}-sg"
  description = "Security group for KiroGuard EC2 plus Caddy HTTPS"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP for Lets Encrypt ACME challenges and redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS for IDE MCP connection"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg" }
}

# ─── IAM Role & Instance Profile for EC2 ─────────────────────────────────────

resource "aws_iam_role" "ec2_role" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project_name}-ec2-role" }
}

resource "aws_iam_policy" "kiroguard_policy" {
  name        = "${var.project_name}-ec2-policy"
  description = "Bedrock, Secrets Manager, SSM and CloudWatch policy for KiroGuard EC2"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = var.bedrock_model_arns
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = ["*"]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.kiroguard_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# ─── Elastic IP ─────────────────────────────────────────────────────────────

resource "aws_eip" "kiroguard" {
  domain = "vpc"

  tags = { Name = "${var.project_name}-eip" }
}

# ─── EC2 Instance ───────────────────────────────────────────────────────────

resource "aws_instance" "kiroguard" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.kiroguard.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  key_name             = var.key_name != "" ? var.key_name : null
  user_data_replace_on_change = true

  user_data = <<-EOF
              #!/bin/bash
              exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
              echo "Starting KiroGuard provisioning..."

              # Install Docker and Git
              dnf install -y docker git
              systemctl enable --now docker
              usermod -aG docker ec2-user

              # Install Docker Compose plugin
              dnf install -y docker-compose-plugin || {
                mkdir -p /usr/libexec/docker/cli-plugins
                curl -SL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64 -o /usr/libexec/docker/cli-plugins/docker-compose
                chmod +x /usr/libexec/docker/cli-plugins/docker-compose
              }

              # Create app directory & build KiroGuard container
              mkdir -p /opt/kiroguard
              git clone https://github.com/kronosoft-tech/kiroguard.git /opt/kiroguard-src || true
              if [ -d /opt/kiroguard-src ]; then
                docker build -t kiroguard:local /opt/kiroguard-src || docker pull ${var.container_image}
              fi

              cd /opt/kiroguard

              # Write Caddyfile for FreeDNS / nip.io HTTPS & SSE reverse proxying
              cat << 'CADDY_EOF' > /opt/kiroguard/Caddyfile
              ${var.freedns_domain} {
                  header {
                      Cache-Control "no-cache"
                      X-Accel-Buffering "no"
                  }
                  reverse_proxy localhost:3000 {
                      flush_interval -1
                  }
              }
              CADDY_EOF

              # Write docker-compose.yml
              cat << 'COMPOSE_EOF' > /opt/kiroguard/docker-compose.yml
              services:
                kiroguard:
                  image: kiroguard:local
                  container_name: kiroguard
                  restart: always
                  network_mode: "host"
                  environment:
                    - KIROGUARD_TRANSPORT=sse
                    - KIROGUARD_PORT=3000
                    - KIROGUARD_LOG_FORMAT=json
                    - AWS_REGION=${var.aws_region}
                  command: ["-transport", "sse", "-port", "3000", "-log-format", "json"]

                caddy:
                  image: caddy:2-alpine
                  container_name: kiroguard-caddy
                  restart: always
                  network_mode: "host"
                  volumes:
                    - /opt/kiroguard/Caddyfile:/etc/caddy/Caddyfile
                    - caddy_data:/data
                    - caddy_config:/config

              volumes:
                caddy_data:
                caddy_config:
              COMPOSE_EOF

              # Start services with docker compose
              docker compose -f /opt/kiroguard/docker-compose.yml up -d || /usr/libexec/docker/cli-plugins/docker-compose -f /opt/kiroguard/docker-compose.yml up -d
              echo "KiroGuard provisioning finished successfully."
              EOF

  tags = { Name = "${var.project_name}-ec2" }
}

resource "aws_eip_association" "kiroguard" {
  instance_id   = aws_instance.kiroguard.id
  allocation_id = aws_eip.kiroguard.id
}
