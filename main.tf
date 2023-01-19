# you will need 2 provider block, set alias provider for replication bucket

provider "aws" {
    
    region = var.primary_region

}
provider "aws" {
    alias ="secondary_region"
    region = var.secondary_region
}

data "aws_caller_identity" "current" {
  
}
resource "aws_s3_bucket" "primary_bucket" {
    
  bucket = "backend-${data.aws_caller_identity.current.account_id}-primary-region"
  lifecyle {
    prevent_destroy =true
  }
}

resource "aws_s3_bucket_acl" "primary_bucket_acl" {
    bucket = aws_s3_bucket.primary_bucket.id
    acl = "private"
  
}

# can implement a lifetime policy to remove versions of a particular age
resource "aws_s3_bucket_versioning" "bucket_version" {
  bucket = aws_s3_bucket.primary_bucket.id
  versioning_configuration {
    status ="Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "primary_bucket_block" {
    bucket = aws_s3_bucket.primary_bucket.id

    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets =true
  
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary_bucket_encryption" {
  
  bucket   = aws_s3_bucket.primary_bucket.id

  rule {
    apply_server_side_encryption_by_default {
     # kms_master_key_id = aws_kms_key.encrypt-primary-region.arn
      sse_algorithm     = "AES256" # or use AES256 aws:kmsif kms is not used
    }
  }
}
# this allows fo replication into another region
resource "aws_s3_bucket_replication_configuration" "primary_backend_bucket_replication" {
  bucket   = aws_s3_bucket.primary_bucket.id
  role     = aws_iam_role.replication.arn


  rule {
    id       = "0"
    priority = "0"
    status   = "Enabled"
    # use below if using kms to encrypt
    #source_selection_criteria {
     # sse_kms_encrypted_objects {
     #   status = "Enabled"
     # }
   # }

    destination {
      bucket        = aws_s3_bucket.secondary_bucket.arn
      storage_class = "STANDARD"
      #use below is kms encrypted
      #encryption_configuration {
       # replica_kms_key_id = aws_kms_key.encrypt-secondary-region.arn
      #}
    }
  }
}

resource "aws_s3_bucket" "secondary_bucket" {
  provider = aws.secondary_region
  bucket   = "backend-${data.aws_caller_identity.current.account_id}-secondary-region"
  tags = {
    "Name" = "backend-${data.aws_caller_identity.current.account_id}-secondary-region"
  }
}

resource "aws_s3_bucket_versioning" "secondary_bucket_versioning" {
  provider = aws.secondary_region
  bucket   = aws_s3_bucket.secondary_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary_bucket_encryption" {
  provider = aws.secondary_region
  bucket   = aws_s3_bucket.secondary_bucket.id

  rule {
    apply_server_side_encryption_by_default {
     # kms_master_key_id = aws_kms_key.encrypt_secondary_region.arn
      sse_algorithm     = "AES256" # or use AES256 aws:kmsif kms is not used
    }
  }
}

resource "aws_s3_bucket_acl" "secondary_bucket_acl" {
    provider = aws.secondary_region
    bucket = aws_s3_bucket.secondary_bucket.id
    acl = "private"
  
}

resource "aws_s3_bucket_public_access_block" "secondary_bucket" {
  provider = aws.secondary_region

  bucket = aws_s3_bucket.secondary_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# replication policy

resource "aws_iam_role" "replication" {

  name     = "s3-terraform-backend-replication"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
POLICY
}
# if kms is not used to encrypt and decrypt please remove permissions
resource "aws_iam_policy" "replication" {

  name     = "s3-terraform-backend-replication-policy"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetReplicationConfiguration",
                "s3:ListBucket"
            ],
            "Effect": "Allow",
            "Resource": [
                "${aws_s3_bucket.primary_bucket.arn}"
            ]
        },
        {
            "Action": [
                "s3:GetObjectVersionForReplication",
                "s3:GetObjectVersionAcl",
                "s3:GetObjectVersionTagging"
            ],
            "Effect": "Allow",
            "Resource": [
                "${aws_s3_bucket.primary_bucket.arn}/*"
            ]
        },
        {
            "Action": [
                "s3:ReplicateObject",
                "s3:ReplicateDelete",
                "s3:ReplicateTags"
            ],
            "Effect": "Allow",
            "Condition": {
                "StringLikeIfExists": {
                    "s3:x-amz-server-side-encryption": [
                        "aws:kms",
                        "AES256"
                    ],
                    "s3:x-amz-server-side-encryption-aws-kms-key-id": [
                        "${aws_kms_key.encrypt_secondary_region.arn}"
                    ]
                }
            },
            "Resource": "${aws_s3_bucket.secondary_bucket.arn}/*"
        },
        {
            "Action": [
                "kms:Decrypt"
            ],
            "Effect": "Allow",
            "Condition": {
                "StringLike": {
                    "kms:ViaService": "s3.${var.primary_region}.amazonaws.com",
                    "kms:EncryptionContext:aws:s3:arn": [
                        "${aws_s3_bucket.primary_bucket.arn}/*"
                    ]
                }
            },
            "Resource": [
                "${aws_kms_key.encrypt_primary_region.arn}"
            ]
        },
        {
            "Action": [
                "kms:Encrypt"
            ],
            "Effect": "Allow",
            "Condition": {
                "StringLike": {
                    "kms:ViaService": "s3.${var.primary_region}.amazonaws.com",
                    "kms:EncryptionContext:aws:s3:arn": [
                        "${aws_s3_bucket.primary_backend_bucket.arn}/*"
                    ]
                }
            },
            "Resource": [
                "${aws_kms_key.encrypt_primary_region.arn}"
            ]
        },
        {
            "Action": [
                "kms:Encrypt"
            ],
            "Effect": "Allow",
            "Condition": {
                "StringLike": {
                    "kms:ViaService": "s3.${var.secondary_region}.amazonaws.com",
                    "kms:EncryptionContext:aws:s3:arn": [
                        "${aws_s3_bucket.secondary_bucket.arn}/*"
                    ]
                }
            },
            "Resource": [
                "${aws_kms_key.encrypt_secondary_region.arn}"
            ]
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "replication" {

  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}

# dynamoDB
resource "aws_dynamodb_table" "dynamo_state_table" {
  
  name = "name_of_table"
  billing_mode = "PAY_PER_REQUEST"
  hush_key ="LockID"
  stream_enabled = true
  steam_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name ="LockID"
    type ="S"
  }

  replica {
    region =var.secondary_region
  }

  tags = {
    "Name" = "backend-${data.aws_caller_identity.current.account_id}"
  }
}

#If kms is used uncomment

# KMS Resources

/*resource "aws_kms_key" "encrypt_primary_region" {

  description             = "Terraform backend KMS key."
  deletion_window_in_days = 30
  enable_key_rotation     = "true"
  tags = {
    "Name" = "remote-backend-${data.aws_caller_identity.current.account_id}-primary-region-kms-key"
  }
}

resource "aws_kms_alias" "encrypt_alias_primary_region" {

  name          = "alias/remote-backend-${data.aws_caller_identity.current.account_id}-kms-key"
  target_key_id = aws_kms_key.encrypt_primary_region.key_id
}

resource "aws_kms_key" "encrypt_secondary_region" {
  provider = aws.secondary_region

  description             = "Terraform backend KMS key."
  deletion_window_in_days = 30
  enable_key_rotation     = "true"
  tags = {
    "Name" = "remote-backend-${data.aws_caller_identity.current.account_id}-secondary-region-kms-key"
  }
}

resource "aws_kms_alias" "encrypt_alias_secondary_region" {
  provider = aws.secondary_region

  name          = "alias/remote-backend-${data.aws_caller_identity.current.account_id}-kms-key"
  target_key_id = aws_kms_key.encrypt_secondary_region.key_id 
}*/