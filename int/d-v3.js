// ===================== v3: Cloud IAM lab, protocol walkthroughs, mock interviews =====================

// ---------- Simplified IAM policy evaluator (single partition; covers the cases interviews probe) ----------
(function(){
 const reEsc=s=>s.replace(/[.+^${}()|[\]\\]/g,"\\$&");
 const wild=(pat,str,ci)=>{if(ci){pat=pat.toLowerCase();str=str.toLowerCase()}return new RegExp("^"+pat.split("*").map(p=>p.split("?").map(reEsc).join(".")).join(".*")+"$").test(str)};
 const arr=x=>x==null?[]:Array.isArray(x)?x:[x];
 const subst=(v,ctx)=>String(v).replace(/\$\{([^}]+)\}/g,(_,k)=>ctx[k]!=null?ctx[k]:"__missing__");
 function condOk(cond,ctx){
  for(const op in (cond||{})){
   for(const key in cond[op]){
    const want=arr(cond[op][key]).map(v=>subst(v,ctx));
    const k=Object.keys(ctx).find(c=>c.toLowerCase()===key.toLowerCase());
    const have=k===undefined?undefined:String(ctx[k]);
    const neg=/Not/.test(op);
    if(have===undefined){if(!neg)return false;continue}
    let m;
    if(/^String(Not)?Equals$/.test(op)||/^Arn(Not)?Equals$/.test(op))m=want.includes(have);
    else if(/^String(Not)?EqualsIgnoreCase$/.test(op))m=want.map(x=>x.toLowerCase()).includes(have.toLowerCase());
    else if(/^(String|Arn)(Not)?Like$/.test(op))m=want.some(w=>wild(w,have,false));
    else if(op==="Bool")m=want.map(x=>String(x).toLowerCase()).includes(have.toLowerCase());
    else return false; // unsupported operator: fail closed
    if(neg?m:!m)return false;
   }
  }
  return true;
 }
 function principalOk(p,req){
  if(p===undefined)return true; // identity policies have no Principal
  if(p==="*")return true;
  const vals=[].concat(...Object.entries(p).map(([t,v])=>arr(v).map(x=>[t,x])));
  return vals.some(([t,v])=>{
   if(v==="*")return true;
   if(t==="Service")return req.principal===v;
   if(/^arn:aws:iam::\d+:root$/.test(v))return req.principalAccount===v.split(":")[4];
   if(/^\d{12}$/.test(v))return req.principalAccount===v;
   return wild(v,req.principal,false);
  });
 }
 function stmtMatches(s,req,isResource){
  if(isResource&&!principalOk(s.Principal,req))return false;
  const actOk=s.NotAction?!arr(s.NotAction).some(a=>wild(a,req.action,true)):arr(s.Action).some(a=>wild(a,req.action,true));
  if(!actOk)return false;
  const res=req.resource;
  const resOk=s.NotResource?!arr(s.NotResource).some(r=>wild(subst(r,req.ctx||{}),res,false)):arr(s.Resource||"*").some(r=>wild(subst(r,req.ctx||{}),res,false));
  if(!resOk)return false;
  return condOk(s.Condition,req.ctx||{});
 }
 function scan(doc,req,isResource,effect){return arr(doc&&doc.Statement).filter(s=>s.Effect===effect&&stmtMatches(s,req,isResource))}
 window.IAM_EVAL=function(pol,req){
  const steps=[];const idDocs=arr(pol.identity),scps=pol.scp?arr(pol.scp):null,bnd=pol.boundary||null,rp=pol.resource||null;
  const denies=[...idDocs.flatMap(d=>scan(d,req,false,"Deny")),...(scps||[]).flatMap(d=>scan(d,req,false,"Deny")),...(bnd?scan(bnd,req,false,"Deny"):[]),...(rp?scan(rp,req,true,"Deny"):[])];
  if(denies.length){steps.push("An explicit Deny matches ("+(denies[0].Sid||"unnamed statement")+"). Explicit deny always wins.");return {decision:"Deny",steps}}
  steps.push("No explicit Deny matches.");
  if(scps){const ok=scps.every(d=>scan(d,req,false,"Allow").length>0);if(!ok){steps.push("The SCP does not allow this action, so the account can't grant it, whatever IAM says.");return {decision:"Deny",steps}}steps.push("SCPs allow it.")}
  if(bnd){if(!scan(bnd,req,false,"Allow").length){steps.push("The permission boundary doesn't allow it. Boundaries cap the maximum permissions.");return {decision:"Deny",steps}}steps.push("The permission boundary allows it.")}
  const idA=idDocs.some(d=>scan(d,req,false,"Allow").length>0),resA=rp?scan(rp,req,true,"Allow").length>0:false;
  steps.push("Identity policy "+(idA?"allows":"does not allow")+" it"+(rp?"; resource policy "+(resA?"allows":"does not allow")+" this principal":"")+".");
  const cross=req.resourceAccount&&req.principalAccount&&req.resourceAccount!==req.principalAccount;
  if(cross){const ok=idA&&resA;steps.push(cross?"Cross-account request: both the caller's identity policy and the resource policy must allow it.":"");return {decision:ok?"Allow":"Deny",steps}}
  const ok=idA||resA;steps.push(ok?"Same account: an Allow from either identity or resource policy is enough.":"Nothing allows it, so the default implicit deny applies.");
  return {decision:ok?"Allow":"Deny",steps};
 };
})();

// ---------- Predict the decision ----------
window.IAM_PREDICT=[
{id:"p1",title:"Explicit deny beats admin",story:"A developer role has AdministratorAccess, plus a second policy denying s3:DeleteBucket. They try to delete a bucket.",
 pol:{identity:[{Statement:[{Sid:"Admin",Effect:"Allow",Action:"*",Resource:"*"}]},{Statement:[{Sid:"NoBucketDelete",Effect:"Deny",Action:"s3:DeleteBucket",Resource:"*"}]}]},
 req:{principal:"arn:aws:iam::111111111111:role/dev",principalAccount:"111111111111",action:"s3:DeleteBucket",resource:"arn:aws:s3:::prod-data",resourceAccount:"111111111111",ctx:{}},
 lesson:"Explicit Deny overrides every Allow, including admin. That's why guardrails are written as Deny statements."},
{id:"p2",title:"SCP blocks a region",story:"The org SCP denies everything outside eu-west-1 except IAM. An admin launches an instance in us-east-1.",
 pol:{scp:[{Statement:[{Sid:"AllowAll",Effect:"Allow",Action:"*",Resource:"*"},{Sid:"RegionLock",Effect:"Deny",NotAction:["iam:*","sts:*","organizations:*"],Resource:"*",Condition:{StringNotEquals:{"aws:RequestedRegion":"eu-west-1"}}}]}],identity:[{Statement:[{Effect:"Allow",Action:"*",Resource:"*"}]}]},
 req:{principal:"arn:aws:iam::111111111111:role/admin",principalAccount:"111111111111",action:"ec2:RunInstances",resource:"arn:aws:ec2:us-east-1:111111111111:instance/*",resourceAccount:"111111111111",ctx:{"aws:RequestedRegion":"us-east-1"}},
 lesson:"SCPs set the ceiling for an account. Even full admin can't act outside them. Note NotAction keeps global services like IAM working."},
{id:"p3",title:"Permission boundary caps a role",story:"A team can create roles, but every role must have a boundary allowing only S3 and DynamoDB. A role with an admin policy calls iam:CreateUser.",
 pol:{boundary:{Statement:[{Effect:"Allow",Action:["s3:*","dynamodb:*"],Resource:"*"}]},identity:[{Statement:[{Effect:"Allow",Action:"*",Resource:"*"}]}]},
 req:{principal:"arn:aws:iam::111111111111:role/team-app",principalAccount:"111111111111",action:"iam:CreateUser",resource:"arn:aws:iam::111111111111:user/x",resourceAccount:"111111111111",ctx:{}},
 lesson:"Effective permissions are the intersection of the identity policy and the boundary. This is how you let teams create roles without escalating."},
{id:"p4",title:"Cross-account read with only a bucket policy",story:"Account B's analytics role wants to read a bucket in account A. The bucket policy allows that role. The role's own identity policy grants nothing for S3.",
 pol:{identity:[{Statement:[{Effect:"Allow",Action:"dynamodb:*",Resource:"*"}]}],resource:{Statement:[{Effect:"Allow",Principal:{AWS:"arn:aws:iam::222222222222:role/analytics"},Action:"s3:GetObject",Resource:"arn:aws:s3:::a-reports/*"}]}},
 req:{principal:"arn:aws:iam::222222222222:role/analytics",principalAccount:"222222222222",action:"s3:GetObject",resource:"arn:aws:s3:::a-reports/q3.csv",resourceAccount:"111111111111",ctx:{}},
 lesson:"Cross-account needs both sides: the resource policy in A and an identity policy in B. Missing either one is the usual cause of 'it's allowed but still denied'."},
{id:"p5",title:"Same-account access through the bucket policy alone",story:"In one account, a role has no S3 permissions, but the bucket policy grants that role GetObject.",
 pol:{identity:[{Statement:[{Effect:"Allow",Action:"sqs:*",Resource:"*"}]}],resource:{Statement:[{Effect:"Allow",Principal:{AWS:"arn:aws:iam::111111111111:role/worker"},Action:"s3:GetObject",Resource:"arn:aws:s3:::jobs/*"}]}},
 req:{principal:"arn:aws:iam::111111111111:role/worker",principalAccount:"111111111111",action:"s3:GetObject",resource:"arn:aws:s3:::jobs/1.json",resourceAccount:"111111111111",ctx:{}},
 lesson:"Within one account, a resource policy naming the principal is enough on its own (for S3 and most services). That's why reviewing bucket policies matters even when IAM roles look tight. KMS key policies and role trust policies have their own rules."},
{id:"p6",title:"Bucket restricted to a VPC endpoint",story:"The bucket policy denies GetObject unless the request comes through VPC endpoint vpce-1a2b. An admin downloads from their laptop.",
 pol:{identity:[{Statement:[{Effect:"Allow",Action:"*",Resource:"*"}]}],resource:{Statement:[{Sid:"OnlyViaVpce",Effect:"Deny",Principal:"*",Action:"s3:GetObject",Resource:"arn:aws:s3:::pii-store/*",Condition:{StringNotEquals:{"aws:SourceVpce":"vpce-1a2b"}}}]}},
 req:{principal:"arn:aws:iam::111111111111:user/admin",principalAccount:"111111111111",action:"s3:GetObject",resource:"arn:aws:s3:::pii-store/c.csv",resourceAccount:"111111111111",ctx:{}},
 lesson:"Deny-unless conditions on the resource restrict even admins. The key is absent from a laptop request, and negated operators treat a missing key as a match, so the Deny applies."},
{id:"p7",title:"Tag-based access (ABAC)",story:"Developers may start or stop only instances tagged with their own team. A payments developer stops an instance tagged team=search.",
 pol:{identity:[{Statement:[{Effect:"Allow",Action:["ec2:StartInstances","ec2:StopInstances"],Resource:"*",Condition:{StringEquals:{"aws:ResourceTag/team":"${aws:PrincipalTag/team}"}}}]}]},
 req:{principal:"arn:aws:iam::111111111111:role/dev-payments",principalAccount:"111111111111",action:"ec2:StopInstances",resource:"arn:aws:ec2:eu-west-1:111111111111:instance/i-0abc",resourceAccount:"111111111111",ctx:{"aws:ResourceTag/team":"search","aws:PrincipalTag/team":"payments"}},
 lesson:"ABAC scales better than one policy per team, but tags become security controls: stop people changing their own tags or resource tags (deny ec2:CreateTags/DeleteTags on the team key)."}
];

// ---------- Write the policy ----------
window.IAM_WRITE=[
{id:"w1",title:"Lambda that reads one folder",task:"Write the identity policy for a reporting Lambda. It must read objects under reports/ in bucket acme-data and nothing else.",
 tests:[["s3:GetObject","arn:aws:s3:::acme-data/reports/2026-10.csv",{},"Allow"],["s3:GetObject","arn:aws:s3:::acme-data/payroll/salaries.csv",{},"Deny"],["s3:PutObject","arn:aws:s3:::acme-data/reports/x.csv",{},"Deny"],["s3:GetObject","arn:aws:s3:::other-bucket/reports/a.csv",{},"Deny"],["s3:DeleteObject","arn:aws:s3:::acme-data/reports/x.csv",{},"Deny"]],
 starter:`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}`,
 sol:`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ReadReportsOnly",
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::acme-data/reports/*"
  }]
}`,
 say:"Start from what the code actually calls, scope to the exact prefix, and if it needs to list the folder, add s3:ListBucket on the bucket ARN with an s3:prefix condition."},
{id:"w2",title:"PassRole without escalation",task:"A deployment role must be able to pass app-lambda-role to Lambda only. It must not pass any other role, or pass app-lambda-role to another service.",
 tests:[["iam:PassRole","arn:aws:iam::111111111111:role/app-lambda-role",{"iam:PassedToService":"lambda.amazonaws.com"},"Allow"],["iam:PassRole","arn:aws:iam::111111111111:role/admin-role",{"iam:PassedToService":"lambda.amazonaws.com"},"Deny"],["iam:PassRole","arn:aws:iam::111111111111:role/app-lambda-role",{"iam:PassedToService":"ec2.amazonaws.com"},"Deny"],["iam:CreateRole","arn:aws:iam::111111111111:role/new",{},"Deny"]],
 starter:`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*"
    }
  ]
}`,
 sol:`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PassOnlyAppRoleToLambda",
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::111111111111:role/app-lambda-role",
    "Condition": { "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" } }
  }]
}`,
 say:"PassRole on * plus any compute-creation permission is an escalation path. Scope it to the exact role ARN and add iam:PassedToService."},
{id:"w3",title:"Tenant-isolated DynamoDB access",task:"A service role for tenant-42 may read and write items in table orders only where the partition key is tenant-42. No table-level admin actions.",
 tests:[["dynamodb:GetItem","arn:aws:dynamodb:eu-west-1:111111111111:table/orders",{"dynamodb:LeadingKeys":"tenant-42"},"Allow"],["dynamodb:PutItem","arn:aws:dynamodb:eu-west-1:111111111111:table/orders",{"dynamodb:LeadingKeys":"tenant-42"},"Allow"],["dynamodb:GetItem","arn:aws:dynamodb:eu-west-1:111111111111:table/orders",{"dynamodb:LeadingKeys":"tenant-7"},"Deny"],["dynamodb:DeleteTable","arn:aws:dynamodb:eu-west-1:111111111111:table/orders",{},"Deny"],["dynamodb:GetItem","arn:aws:dynamodb:eu-west-1:111111111111:table/users",{"dynamodb:LeadingKeys":"tenant-42"},"Deny"]],
 starter:`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "dynamodb:*",
      "Resource": "arn:aws:dynamodb:eu-west-1:111111111111:table/*"
    }
  ]
}`,
 sol:`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "OwnTenantItemsOnly",
    "Effect": "Allow",
    "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"],
    "Resource": "arn:aws:dynamodb:eu-west-1:111111111111:table/orders",
    "Condition": { "StringEquals": { "dynamodb:LeadingKeys": "tenant-42" } }
  }]
}`,
 say:"In real AWS this uses ForAllValues:StringEquals with a principal tag variable, so one policy serves every tenant. The lab simplifies the condition, but say the real form in interviews."},
{id:"w4",title:"KMS decrypt only through S3",task:"An app role may use KMS key 1234abcd to decrypt only when the call comes through S3 in us-east-1 (no direct kms:Decrypt from the app), and must not manage the key.",
 tests:[["kms:Decrypt","arn:aws:kms:us-east-1:111111111111:key/1234abcd",{"kms:ViaService":"s3.us-east-1.amazonaws.com"},"Allow"],["kms:Decrypt","arn:aws:kms:us-east-1:111111111111:key/1234abcd",{},"Deny"],["kms:Decrypt","arn:aws:kms:us-east-1:111111111111:key/9999ffff",{"kms:ViaService":"s3.us-east-1.amazonaws.com"},"Deny"],["kms:ScheduleKeyDeletion","arn:aws:kms:us-east-1:111111111111:key/1234abcd",{},"Deny"]],
 starter:`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}`,
 sol:`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DecryptViaS3Only",
    "Effect": "Allow",
    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
    "Resource": "arn:aws:kms:us-east-1:111111111111:key/1234abcd",
    "Condition": { "StringEquals": { "kms:ViaService": "s3.us-east-1.amazonaws.com" } }
  }]
}`,
 say:"kms:ViaService ties key use to a service, so stolen app credentials can't decrypt data directly. Key administration belongs to a separate role (separation of duties)."},
{id:"w5",title:"Guardrail SCP",task:"Write an SCP (identity-style statements are fine here) that allows everything except stopping or deleting CloudTrail trails and disabling GuardDuty.",
 tests:[["cloudtrail:StopLogging","arn:aws:cloudtrail:us-east-1:111111111111:trail/org",{},"Deny"],["cloudtrail:DeleteTrail","arn:aws:cloudtrail:us-east-1:111111111111:trail/org",{},"Deny"],["guardduty:DeleteDetector","arn:aws:guardduty:us-east-1:111111111111:detector/abc",{},"Deny"],["s3:GetObject","arn:aws:s3:::any/x",{},"Allow"],["cloudtrail:LookupEvents","*",{},"Allow"]],
 starter:`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}`,
 sol:`{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "AllowAll", "Effect": "Allow", "Action": "*", "Resource": "*" },
    { "Sid": "ProtectLogging", "Effect": "Deny",
      "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                 "guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount", "guardduty:UpdateDetector"],
      "Resource": "*" }
  ]
}`,
 say:"Guardrails are Deny statements in SCPs so no one in the account, including admins, can blind you. Exempt a break-glass role with a condition on aws:PrincipalArn if needed."}
];

// ---------- Privilege escalation puzzles ----------
window.IAM_PRIVESC=[
{id:"e1",perms:["iam:PassRole on *","lambda:CreateFunction","lambda:InvokeFunction"],ctx:"An admin-equivalent role 'ops-admin' exists and trusts Lambda.",
 opts:["No escalation: they can't attach policies","Create a Lambda with ops-admin as its role, invoke it, and run admin actions from inside","Read ops-admin's access keys from IAM"],ans:1,
 why:"PassRole + create compute + invoke = run code as any passable role. Fix: scope PassRole to specific role ARNs with iam:PassedToService."},
{id:"e2",perms:["iam:CreatePolicyVersion on the policy attached to themselves"],ctx:"A customer-managed policy 'dev-policy' is attached to the user.",
 opts:["Create a new default version of dev-policy that allows *","Nothing: versions need approval","Only read other versions"],ans:0,
 why:"CreatePolicyVersion with --set-as-default rewrites your own permissions. Restrict policy-management actions to an admin pipeline."},
{id:"e3",perms:["iam:UpdateAssumeRolePolicy on role 'prod-deploy'","sts:AssumeRole"],ctx:"prod-deploy has wide production permissions.",
 opts:["Can only read the trust policy","Edit prod-deploy's trust policy to trust themselves, then assume it","Needs PassRole first"],ans:1,
 why:"Changing who a role trusts is as powerful as the role itself. Treat trust policy changes as admin actions and alert on UpdateAssumeRolePolicy."},
{id:"e4",perms:["ssm:SendCommand on all instances"],ctx:"A build server EC2 instance runs with an instance profile that has admin rights.",
 opts:["Only run commands as a normal OS user","Run commands on the build server and use its instance role credentials","SSM is read-only"],ans:1,
 why:"Running code on an instance means inheriting its role. Scope SendCommand by instance tags and keep instance roles least-privilege."},
{id:"e5",perms:["lambda:UpdateFunctionCode on all functions"],ctx:"A function 'user-sync' runs with a role that can write to IAM.",
 opts:["Overwrite user-sync's code to perform IAM actions with its role","Only change environment variables","Needs CreateFunction"],ans:0,
 why:"Updating code of a privileged function is code execution as that role. Restrict per function ARN; require deployments through the pipeline."},
{id:"e6",perms:["iam:CreateAccessKey on users/*"],ctx:"An IAM user 'legacy-admin' still exists.",
 opts:["Only for their own user","Create a new access key for legacy-admin and use it","Keys need MFA"],ans:1,
 why:"CreateAccessKey on other users is takeover. Scope to ${aws:username} and remove legacy IAM users in favour of SSO."},
{id:"e7",perms:["ec2:RunInstances","iam:PassRole on *","ec2:DescribeInstances"],ctx:"An instance profile 'data-admin' exists.",
 opts:["Launch an instance with data-admin and read its credentials from the metadata service","EC2 can't use roles","Only works with SSH keys"],ans:0,
 why:"Same pattern as Lambda: PassRole + launch compute. GuardDuty can flag instance credentials used from elsewhere."}
];

// ---------- Trust policy fixes ----------
window.IAM_TRUST=[
{id:"r1",title:"Third-party monitoring vendor role",policy:`{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::999988887777:root" },
    "Action": "sts:AssumeRole"
  }]
}`,q:"The vendor's account is shared by all its customers. What's missing?",
 opts:["Nothing, the account ID is specific","An sts:ExternalId condition unique to you, to stop the confused-deputy problem","MFA for the vendor"],ans:1,
 why:"Without a per-customer ExternalId, another customer of the same vendor could trick the vendor into accessing your account."},
{id:"r2",title:"GitHub Actions deploy role",policy:`{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": { "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } }
  }]
}`,q:"What's the risk?",
 opts:["None: the audience is checked","Any repository on GitHub can assume this role, because there is no sub condition","Only forks can assume it"],ans:1,
 why:"Without a condition on token.actions.githubusercontent.com:sub (for example repo:acme/api:ref:refs/heads/main), any GitHub workflow anywhere gets a valid token. This misconfiguration has been found in real organisations."},
{id:"r3",title:"Cross-account role",policy:`{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "*" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-abc123" } }
  }]
}`,q:"Is this safe?",
 opts:["Unsafe: anyone on the internet can assume it","Acceptable: only principals in your organisation can assume it, but it's broad; prefer specific role ARNs for sensitive roles","Invalid policy"],ans:1,
 why:"The PrincipalOrgID condition limits it to your org, so it isn't public. It's still broad: every principal in every account in the org can assume it."},
{id:"r4",title:"Lambda execution role",policy:`{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}`,q:"Anything to add?",
 opts:["It's the normal trust policy for a Lambda role; the risk is in who can pass it (PassRole), not here","Must add ExternalId","Principal must be *"],ans:0,
 why:"Service trust is standard. Control who can attach this role to a function (iam:PassRole) and keep the role's permissions tight."}
];

// ---------- CloudTrail investigation ----------
window.CT_EVENTS=[
 ["02:03:11","GetCallerIdentity","user/ci-deployer","AKIA…7QXZ","185.220.101.4","us-east-1","",""],
 ["02:03:15","ListBuckets","user/ci-deployer","AKIA…7QXZ","185.220.101.4","us-east-1","",""],
 ["02:03:40","ListAttachedUserPolicies","user/ci-deployer","AKIA…7QXZ","185.220.101.4","us-east-1","userName=ci-deployer",""],
 ["02:04:58","CreateUser","user/ci-deployer","AKIA…7QXZ","185.220.101.4","us-east-1","userName=backup-svc",""],
 ["02:05:10","AttachUserPolicy","user/ci-deployer","AKIA…7QXZ","185.220.101.4","us-east-1","backup-svc ← AdministratorAccess",""],
 ["02:05:22","CreateAccessKey","user/ci-deployer","AKIA…7QXZ","185.220.101.4","us-east-1","userName=backup-svc",""],
 ["02:08:47","StopLogging","user/backup-svc","AKIA…M2PL","45.137.21.9","us-east-1","trail=org-trail","AccessDenied"],
 ["02:09:30","RunInstances","user/backup-svc","AKIA…M2PL","45.137.21.9","ap-south-1","8 × p3.8xlarge",""],
 ["02:12:02","GetObject (×1,840)","user/backup-svc","AKIA…M2PL","45.137.21.9","eu-west-1","bucket=customer-exports",""],
 ["02:21:15","PutBucketPolicy","user/backup-svc","AKIA…M2PL","45.137.21.9","eu-west-1","customer-exports: Principal * GetObject","AccessDenied"]
];
window.CT_QS=[
 {q:"How did the attacker get in?",opts:["Phished console password for an admin","Leaked long-lived access key of ci-deployer, used from an unfamiliar IP","SSRF on an EC2 instance"],ans:1,why:"The first events use ci-deployer's access key from a Tor exit IP, starting with GetCallerIdentity, the classic 'whose key is this?' call."},
 {q:"What did they do for persistence?",opts:["Created backup-svc with AdministratorAccess and an access key","Modified the trail","Launched instances"],ans:0,why:"CreateUser → AttachUserPolicy(AdministratorAccess) → CreateAccessKey gives a second, independent way back in. Disabling ci-deployer alone wouldn't stop them."},
 {q:"Which control worked?",opts:["GuardDuty blocked RunInstances","An SCP denied StopLogging and the account-level Block Public Access stopped the public bucket policy","MFA"],ans:1,why:"StopLogging and PutBucketPolicy both got AccessDenied, consistent with an SCP protecting CloudTrail and Block Public Access on S3."},
 {q:"What was the impact?",opts:["None, everything was denied","Crypto-mining in ap-south-1 and likely exfiltration of 1,840 objects from customer-exports","Only reconnaissance"],ans:1,why:"RunInstances succeeded in an unused region (mining) and the GetObject data events show mass reads of customer data, which triggers breach assessment."},
 {q:"First containment steps?",opts:["Delete the trail to stop noise","Disable both access keys, attach a deny-all policy to both users, revoke sessions, snapshot then stop the instances, and preserve logs","Email the team and wait until morning"],ans:1,why:"Cut every credential path (including the backdoor user), stop spend and exfiltration, preserve evidence."},
 {q:"What would have prevented this?",opts:["A stronger password policy","No long-lived CI keys (OIDC federation), least privilege for ci-deployer (no iam:CreateUser), a region-restriction SCP and alerts on IAM changes","Rotating keys every 90 days"],ans:1,why:"Each layer breaks the chain: no key to leak, no permission to create a backdoor, no unused regions, and fast detection."}
];

// ---------- Protocol walkthroughs ----------
window.FLOWS=[
{id:"oauth",title:"OAuth 2.0 code flow with PKCE (BFF)",actors:["Browser","App backend (BFF)","Authorization server","API"],
 steps:[[0,1,"GET /login","User clicks Sign in.","",""],
  [1,0,"302 → /authorize?client_id&redirect_uri&state&code_challenge","BFF creates state (CSRF protection) and a random code_verifier; sends its SHA-256 hash as code_challenge.","Missing state allows login CSRF; loose redirect_uri matching lets attackers steal codes."],
  [0,2,"GET /authorize …","Browser goes to the IdP; user signs in with MFA.","Phishing proxies can capture sessions; passkeys resist this."],
  [2,0,"302 → redirect_uri?code&state","IdP returns a short-lived, single-use code.","Codes leak through Referer or logs; open redirects on the client can forward them."],
  [0,1,"GET /callback?code&state","BFF checks state matches what it stored.","Skipping the state check lets an attacker log the victim into the attacker's account."],
  [1,2,"POST /token code + code_verifier + client auth","Back channel: BFF redeems the code with the verifier.","Without PKCE, a stolen code can be redeemed by the attacker."],
  [2,1,"access_token, refresh_token, id_token","BFF validates the ID token (signature, iss, aud, nonce) and stores tokens server side.","Not validating aud lets tokens for another app be accepted."],
  [1,0,"Set-Cookie: __Host-session; HttpOnly; Secure; SameSite=Lax","Browser only gets a session cookie. No tokens in JavaScript.","Tokens in localStorage would be readable by any XSS."],
  [1,3,"GET /orders  Authorization: Bearer …","BFF calls the API with the access token.","API must validate signature, alg, iss, aud, exp and then authorize the object."]]},
{id:"tls",title:"TLS 1.3 handshake",actors:["Client","Server"],
 steps:[[0,1,"ClientHello: versions, cipher suites, key_share, SNI","Client offers ECDHE key shares up front, enabling one round trip.","SNI is visible; Encrypted Client Hello hides it."],
  [1,0,"ServerHello: chosen suite + key_share","Both sides now compute the shared secret (ECDHE). Everything after this is encrypted.","Downgrade protection: a sentinel in ServerHello.random signals TLS 1.2 downgrade attempts."],
  [1,0,"{EncryptedExtensions, Certificate, CertificateVerify, Finished}","Server proves it owns the certificate's private key by signing the handshake transcript.","Client must validate chain, hostname, validity; skipping this is the classic MITM bug."],
  [0,1,"{Finished}","Client confirms the transcript. Keys are ephemeral, so forward secrecy is always on.",""],
  [0,1,"Application data","Encrypted with AEAD (AES-GCM or ChaCha20-Poly1305).","0-RTT resumption data can be replayed; only allow it for idempotent requests."]]},
{id:"cors",title:"CORS preflight and a credentialed request",actors:["Page on evil.com","Victim's browser","api.example.com"],
 steps:[[0,1,"fetch('https://api.example.com/me', {credentials:'include', method:'PUT'})","Script on another origin tries to call the API with the victim's cookies.",""],
  [1,2,"OPTIONS /me  Origin: https://evil.com","Non-simple request, so the browser asks permission first (preflight).","Simple requests (GET, form POST) skip preflight but are still sent, which is why CORS is not CSRF protection."],
  [2,1,"Access-Control-Allow-Origin: https://evil.com + Allow-Credentials: true","A misconfigured API reflects any Origin.","This reflection plus credentials is the exploitable bug."],
  [1,2,"PUT /me with cookies","Browser sends the real request with cookies.",""],
  [2,1,"200 + account data","Browser lets evil.com read the response because CORS allowed it.","Fix: exact allow-list of origins, no credentials unless needed, Vary: Origin."]]},
{id:"csrf",title:"CSRF attack",actors:["Victim browser","evil.com","bank.example"],
 steps:[[0,2,"Login → Set-Cookie: session","Victim is logged in to the bank.","Cookie without SameSite is sent on cross-site requests in older setups."],
  [0,1,"Visits evil.com","Victim opens an attacker page in another tab.",""],
  [1,0,"<form action=bank/transfer method=POST> auto-submit","Page makes the browser submit a form to the bank.",""],
  [0,2,"POST /transfer (cookie attached automatically)","The bank sees a valid session and performs the transfer.","Defences: SameSite=Lax/Strict, anti-CSRF token tied to the session, Origin header check."]]},
{id:"ssrf",title:"SSRF to cloud credentials",actors:["Attacker","Web app (EC2)","Metadata service 169.254.169.254","AWS APIs"],
 steps:[[0,1,"POST /preview url=http://169.254.169.254/latest/meta-data/iam/security-credentials/","Feature fetches any URL the user gives it.","Allow-list destinations; block link-local and private ranges after DNS resolution."],
  [1,2,"GET metadata (IMDSv1, no token)","The server makes the request from inside.","IMDSv2 requires a PUT for a session token, which most SSRF can't send."],
  [2,1,"AccessKeyId, SecretAccessKey, Token","Temporary credentials for the instance role.",""],
  [1,0,"Response body returned to the user","Full-read SSRF: the attacker sees the credentials.","Never return fetched bodies to users when you can avoid it."],
  [0,3,"aws s3 ls … with stolen credentials","Attacker uses them from their own machine.","GuardDuty: InstanceCredentialExfiltration.OutsideAWS. Least privilege limits damage."]]},
{id:"ghoidc",title:"GitHub Actions to AWS with OIDC (no stored keys)",actors:["GitHub runner","GitHub OIDC provider","AWS STS","AWS resource"],
 steps:[[0,1,"Request ID token (aud=sts.amazonaws.com)","Workflow with id-token: write asks GitHub for a signed JWT.","Only grant id-token: write in workflows that need it."],
  [1,0,"JWT: sub=repo:acme/api:ref:refs/heads/main, aud, iss","Token says exactly which repo, branch and event it came from.",""],
  [0,2,"AssumeRoleWithWebIdentity(role, JWT)","STS validates the signature and the role's trust policy conditions.","Trust policy must pin sub to repo and branch; checking aud alone lets any GitHub repo in."],
  [2,0,"Temporary credentials (1 hour)","Short-lived, nothing to leak long-term.",""],
  [0,3,"Deploy","Pipeline deploys with a scoped role.","Separate roles for plan vs apply; production only from protected branches."]]},
{id:"saml",title:"SAML SP-initiated SSO",actors:["Browser","Service provider (app)","Identity provider"],
 steps:[[0,1,"GET /app","User opens the app, not logged in.",""],
  [1,0,"Redirect with AuthnRequest","App sends the browser to the IdP with a request ID.",""],
  [0,2,"User authenticates at IdP","Password plus MFA at the corporate IdP.",""],
  [2,0,"Auto-POST form with signed SAMLResponse","Assertion with NameID, attributes, audience, recipient, expiry, signed by the IdP.","Attackers tamper with the XML here: signature wrapping, comment injection in NameID."],
  [0,1,"POST /acs SAMLResponse","App validates signature, which element is signed, audience, recipient, time window, InResponseTo.","Accepting unsigned assertions or validating the wrong element leads to account takeover."]]},
{id:"kerb",title:"Kerberos authentication",actors:["Client","KDC: AS","KDC: TGS","Service"],
 steps:[[0,1,"AS-REQ (timestamp encrypted with user's key)","Pre-authentication proves knowledge of the password.","Accounts without pre-auth can be AS-REP roasted (offline cracking)."],
  [1,0,"AS-REP: TGT (encrypted with krbtgt key)","Ticket-granting ticket for the session.","Stealing the krbtgt hash enables golden tickets."],
  [0,2,"TGS-REQ with TGT, for service SPN","Client asks for a ticket to a specific service.",""],
  [2,0,"TGS-REP: service ticket (encrypted with service account key)","Any user can request it.","Kerberoasting: crack service tickets offline if the service account has a weak password."],
  [0,3,"AP-REQ with service ticket","Client presents the ticket; no password sent.","Silver tickets forge service tickets with the service key."]]}
];

// ---------- Mock interview ----------
window.MOCK_FORMATS={
 "45":[["design",15],["code",10],["questions",12],["story",8]],
 "60":[["design",20],["code",10],["cloud",10],["questions",12],["story",8]],
 "30":[["threat",12],["questions",10],["story",8]]
};
