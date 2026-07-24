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

# ─── VPC ────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

# ─── Public Subnets ─────────────────────────────────────────────────────────

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index % length(var.azs)]
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-${count.index}" }
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
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ─── Private Subnets ────────────────────────────────────────────────────────

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index % length(var.azs)]

  tags = { Name = "${var.project_name}-private-${count.index}" }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "${var.project_name}-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "${var.project_name}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = { Name = "${var.project_name}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ─── Security Groups ────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for KiroGuard ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${var.project_name}-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name        = "${var.project_name}-ecs-sg"
  description = "Security group for KiroGuard ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-ecs-sg" }
}

# ─── Application Load Balancer ─────────────────────────────────────────────

resource "aws_lb" "kiroguard" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${var.project_name}-alb" }
}

resource "aws_lb_target_group" "kiroguard" {
  name        = "${var.project_name}-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    port                = 3000
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }

  tags = { Name = "${var.project_name}-tg" }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.kiroguard.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.kiroguard.arn
  }
}

# ─── ECS Cluster ────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "kiroguard" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${var.project_name}-cluster" }
}

resource "aws_ecs_task_definition" "kiroguard" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.kiroguard_task.arn

  container_definitions = jsonencode([
    {
      name      = "kiroguard"
      image     = var.container_image
      essential = true
      portMappings = [
        {
          containerPort = 3000
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "KIROGUARD_TRANSPORT", value = "sse" },
        { name = "KIROGUARD_PORT", value = "3000" },
        { name = "KIROGUARD_LOG_FORMAT", value = "json" },
        { name = "AWS_REGION", value = var.aws_region }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.kiroguard.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "kiroguard"
        }
      }
      healthCheck = {
        command  = ["CMD-SHELL", "wget -qO- http://localhost:3000/healthz || exit 1"]
        interval = 15
        timeout  = 5
        retries  = 3
        startPeriod = 10
      }
    }
  ])

  tags = { Name = "${var.project_name}-task" }
}

resource "aws_ecs_service" "kiroguard" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.kiroguard.id
  task_definition = aws_ecs_task_definition.kiroguard.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.kiroguard.arn
    container_name   = "kiroguard"
    container_port   = 3000
  }

  tags = { Name = "${var.project_name}-service" }
}

# ─── IAM ────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_execution" {
  name = "${var.project_name}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    aws_iam_policy.ecs_execution_custom.arn,
  ]

  tags = { Name = "${var.project_name}-ecs-execution" }
}

resource "aws_iam_policy" "ecs_execution_custom" {
  name        = "${var.project_name}-ecs-execution-custom"
  description = "Custom execution policy for KiroGuard ECS tasks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.kiroguard.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "ssm:GetParameter",
        ]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_role" "kiroguard_task" {
  name = "${var.project_name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project_name}-task" }
}

resource "aws_iam_policy" "kiroguard_task" {
  name        = "${var.project_name}-task-policy"
  description = "Policy for KiroGuard task role — Bedrock + Secrets Manager + SSM"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
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
          "ssm:PutParameter",
        ]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "kiroguard_task" {
  role       = aws_iam_role.kiroguard_task.name
  policy_arn = aws_iam_policy.kiroguard_task.arn
}

# ─── CloudWatch ─────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "kiroguard" {
  name              = "/aws/ecs/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = { Name = "${var.project_name}-logs" }
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.project_name}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "KiroGuard CPU > 80% for 2 minutes"
  dimensions = {
    ClusterName = aws_ecs_cluster.kiroguard.name
    ServiceName = aws_ecs_service.kiroguard.name
  }
}

# ─── AWS WAFv2 (Web Application Firewall) ──────────────────────────────────

resource "aws_wafv2_web_acl" "kiroguard" {
  name        = "${var.project_name}-waf"
  description = "WAF for KiroGuard ALB with rate limiting and AWS Common Rules"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-waf-common-rules"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimit"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 300
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-waf-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf-acl"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${var.project_name}-waf" }
}

resource "aws_wafv2_web_acl_association" "kiroguard" {
  resource_arn = aws_lb.kiroguard.arn
  web_acl_arn  = aws_wafv2_web_acl.kiroguard.arn
}

# ─── SNS Security Notifications (DevSecOps Alerting) ─────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"

  tags = { Name = "${var.project_name}-alerts" }
}

resource "aws_cloudwatch_log_metric_filter" "secrets_detected" {
  name           = "${var.project_name}-secrets-detected-filter"
  pattern        = "{ $.event = \"migration_succeeded\" || $.event = \"secrets_detected\" }"
  log_group_name = aws_cloudwatch_log_group.kiroguard.name

  metric_transformation {
    name      = "SecretsDetectedCount"
    namespace = "KiroGuard/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "secrets_detected_alarm" {
  alarm_name          = "${var.project_name}-secrets-detected-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecretsDetectedCount"
  namespace           = "KiroGuard/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert when KiroGuard detects a high-entropy secret or credential leak"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ─── CloudWatch Real-Time Dashboard ──────────────────────────────────────────

resource "aws_cloudwatch_dashboard" "kiroguard" {
  dashboard_name = "${var.project_name}-executive-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.kiroguard.name, "ServiceName", aws_ecs_service.kiroguard.name],
            [".", "MemoryUtilization", ".", ".", ".", "."]
          ]
          period = 60
          stat   = "Average"
          region = var.aws_region
          title  = "KiroGuard Cluster Health (CPU & Memory)"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.kiroguard.arn_suffix],
            [".", "TargetResponseTime", ".", "."]
          ]
          period = 60
          stat   = "Sum"
          region = var.aws_region
          title  = "ALB Throughput & Target Latency"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          metrics = [
            ["KiroGuard/Security", "SecretsDetectedCount"]
          ]
          period = 60
          stat   = "Sum"
          region = var.aws_region
          title  = "Real-Time DevSecOps Security Detections"
        }
      }
    ]
  })
}
