#! /usr/bin/env python3

import boto3 #type: ignore
import json
import typing
import datetime
from mooncloud_driver import abstract_probe, atom, result, entrypoint # type: ignore

class Probe(abstract_probe.AbstractProbe):
    
    def _serialize_datetimes(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    def requires_credential(self):
       return True
    
    def init(self, inputs=None) -> bool:

        config = self.config.input.get('config')
        # # Local load method
        # access_key_id = config.get('username')
        # secret_access_key = config.get('password')
        access_key_id = self.config.credential.get('username')
        secret_access_key = self.config.credential.get('password')
        region = config.get('region')

        cvss = config.get('cvssthreshold')
        # parse and clamp CVSS threshold
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0
        if cvss >= 10:
            cvss = 10.0
        self.cvss_th = cvss
        self.skip = False
        raw = config.get('targetinstances', ['ALL'])
        if isinstance(raw, str):
            raw = [raw]
        elif not isinstance(raw, list):
            raw = ['ALL']
        allowed = ["AWS_LAMBDA_FUNCTION", "AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE"]
        self.target = [t for t in raw if t in allowed]
        if not self.target:
            self.target = ["ALL"]

        assert access_key_id is not None, "AWS Access Key ID is missing"
        assert secret_access_key is not None, "AWS Secret Access Key is missing"
        
        self.client = boto3.client(
            'inspector2',
            aws_access_key_id = access_key_id,
            aws_secret_access_key = secret_access_key,
            region_name = region or 'eu-central-1'
        )

        self.client.list_members(maxResults=1)

        not_enabled = []
        # verify Inspector2 is enabled for each requested resource type
        types_to_check = (
            ["AWS_ECR_CONTAINER_IMAGE", "AWS_EC2_INSTANCE", "AWS_LAMBDA_FUNCTION"]
            if "ALL" in self.target else self.target
        )
        raw = self.client.batch_get_account_status()
        res = json.loads(json.dumps(raw, default=self._serialize_datetimes))
        accounts = res.get("accounts", [])
        resource_state = accounts[0].get("resourceState", {})

        # map resource types
        key_map = {
            "AWS_EC2_INSTANCE": "ec2",
            "AWS_ECR_CONTAINER_IMAGE": "ecr",
            "AWS_LAMBDA_FUNCTION": "lambda"
        }
        for rt in types_to_check:
            key = key_map.get(rt)
            status = resource_state.get(key, {}).get("status")
            if status != "ENABLED":
                not_enabled.append(rt)
        if not_enabled:
            self.skip = True
            self.result.integer_result = 1
            self.result.pretty_result = "Amazon Inspector2 not enabled for requested resource types"
            self.result.put_raw_extra_data(
                "not_enabled",
                not_enabled
            )
        return True
    
    def cve_scan(self, inputs=None) -> bool:
        """
        CVE Scan - Amazon Inspector findings should be emitted
        """
        if self.skip:
            return False
        
        paginator = self.client.get_paginator("list_findings")
        clean_findings = []
        limit = 1000
        pagconf = {
            "MaxItems": limit, 
            "PageSize": 50
        }

        # create filters variable basing in the array self.target in input
        if "ALL" in self.target:
            resource_types = [
                "AWS_ECR_CONTAINER_IMAGE",
                "AWS_EC2_INSTANCE",
                "AWS_LAMBDA_FUNCTION"
            ]
            filters = {
                "resourceType": [
                    {"comparison": "EQUALS", "value": rt}
                    for rt in resource_types
                ]
            }
        else:
            filters = {"resourceType": []}
            for rt in self.target:
                filters["resourceType"].append({
                    "comparison": "EQUALS",
                    "value": rt
                })

        sort = {
            "field": "INSPECTOR_SCORE",
            "sortOrder": "DESC"
        }
        above_th = False
        tot_ctr = 0
        above_ctr = 0
        # collect all findings, normalize dates
        for page in paginator.paginate(PaginationConfig=pagconf, sortCriteria=sort, filterCriteria=filters):
            for f in page.get("findings", []):
                clean = json.loads(json.dumps(f, default=self._serialize_datetimes))
                clean_findings.append(clean)

        if not clean_findings:
            self.result.integer_result = 0
            self.result.pretty_result = "CVE Scan - Amazon Inspector findings not found: no vulnerabilities detected"
            return True

        # one ExtradataCVE per finding
        seen_cve_ids = set()
        for finding in clean_findings:
            # compute CVE ID and skip duplicates
            cve_id = (
                finding.get('packageVulnerabilityDetails', {})
                       .get('vulnerabilityId')
                or finding.get('cve', {}).get('cveId')
            )
            if not cve_id or cve_id in seen_cve_ids:
                continue
            seen_cve_ids.add(cve_id)
            
            vuln        = finding.get('packageVulnerabilityDetails', {})
            cve_id      = vuln.get('vulnerabilityId') or finding.get('cve', {}).get('cveId')
            title       = finding.get('title', '')
            description = finding.get('description', '')
            severity    = finding.get('severity', '')
            cvss_entries= vuln.get('cvss', [])
            cvss_score  = str(cvss_entries[0].get('baseScore')) if cvss_entries else ""
            cwe_objs = [
                result.ExtradataCWE(id=c.get('cweId',''), name=c.get('cweName',''))
                for c in vuln.get('relatedVulnerabilities', [])
                if isinstance(c, dict)
            ]

            cve_obj = result.ExtradataCVE(
                id=cve_id,
                name=title,
                cwe=cwe_objs,
                description=description,
                cvss=cvss_score,
                severity=severity
            )
            self.result.put_refined_extra_data_cve(cve_obj)
            tot_ctr += 1
            try:
                if float(cvss_score) >= self.cvss_th:
                    above_ctr += 1
                    above_th = True
            except ValueError:
                pass
        
        if above_th:
            self.result.integer_result = 1
            self.result.pretty_result = f"Found {above_ctr} out of {tot_ctr} vulnerabilities with CVSS higher than {self.cvss_th}"
        else:
            self.result.integer_result = 0
            self.result.pretty_result = f"All {tot_ctr} vulnerabilities below CVSS threshold: {self.cvss_th}"
        return True
    
    def atoms(self) -> typing.Sequence[atom.AtomPairWithException]:
        return [
            atom.AtomPairWithException(
                forward=self.init,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=lambda e: result.Result(
                            integer_result=2,
                            pretty_result="Credential error: AWS credentials missing or invalid",
                            base_extra_data=result.Extradata(raw={"ExceptionRecovered": str(e)})
                        )
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.cve_scan,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            )
        ]

if __name__ == "__main__":
    entrypoint.start_execution(Probe)
