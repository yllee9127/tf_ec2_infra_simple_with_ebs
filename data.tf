data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_subnets" "public-1" {
  /*filter {
    name = "vpc-id"
    #values = [var.vpc_id]
    values = [module.vpc-1.vpc_id]
  }*/

  filter {
    name = "tag:Name"
    values = ["yl-vpc-1-public*"]
  }
  depends_on = [module.vpc-1]
}
