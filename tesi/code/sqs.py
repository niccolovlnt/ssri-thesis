#! /usr/bin/env python3

import copy
import re
import boto3 # type: ignore
import os
import requests # type: ignore
import json
import typing
from mooncloud_driver import abstract_probe, atom, result, entrypoint # type: ignore

class Probe(abstract_probe.AbstractProbe):

    def requires_credential(self):
        return True

    def init(self, inputs=None) -> bool: 

        self.control_results = {}
        self.collected_data = {}

        config = self.config.input.get('config')
        # # Local load method
        # access_key_id = config.get('username')
        # secret_access_key = config.get('password')
        access_key_id = self.config.credential.get('username')
        secret_access_key = self.config.credential.get('password')

        raw_regions = ''
        try:
            raw_regions = config.get('region', '')
        except Exception:
            raw_regions = ''
        
        # split on commas, semicolons or whitespace into list
        if isinstance(raw_regions, str):
            raw_regions = raw_regions.strip()
            specific_regions = re.split(r'[,;\s]+', raw_regions) if raw_regions else []
        elif isinstance(raw_regions, list):
            specific_regions = raw_regions
        else:
            specific_regions = []

        #max 6 regions
        if len(specific_regions) > 6:
            specific_regions = specific_regions[:6]
        
        assert access_key_id is not None, "AWS Access Key ID is missing"
        assert secret_access_key is not None, "AWS Secret Access Key is missing"
        
        self.clients = {}
        # ensure at least one region
        if not specific_regions:
            specific_regions = ['eu-central-1']
        for idx, region in enumerate(specific_regions, start=1):
            self.clients[f'client_{idx}'] = boto3.client(
            'sqs',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
            )

        self.clients['client_1'].list_queues(MaxResults=1)

        return True

    def sqs_control_1(self, inputs=None) -> bool:
        """
        SQS Control 1 - Check if SQS queues are encrypted at rest
        """
        region_results = {}

        for client_name, client in self.clients.items():
            region = client.meta.region_name
            response = client.list_queues()

            encrypted_queues = []
            unencrypted_queues = []

            if 'QueueUrls' in response:
                for queue_url in response['QueueUrls']:
                    queue_name = queue_url.split('/')[-1]
                    attr_response = client.get_queue_attributes(
                        AttributeNames=['SqsManagedSseEnabled'],
                        QueueUrl=queue_url
                    )
                    if (attr_response.get('Attributes', {})
                            .get('SqsManagedSseEnabled') == 'true'):
                        encrypted_queues.append({'name': queue_name, 'url': queue_url})
                    else:
                        unencrypted_queues.append({'name': queue_name, 'url': queue_url})
            # store per-region collected_data
            self.collected_data[f"CIS SQS.1 - {region} - Encrypted Queues"] = encrypted_queues
            self.collected_data[f"CIS SQS.1 - {region} - Unencrypted Queues"] = unencrypted_queues

            # compute pass/fail & message per region
            passed = (len(unencrypted_queues) == 0)
            if 'QueueUrls' not in response:
                pretty = "No SQS queues found in the account"
            elif unencrypted_queues:
                pretty = (
                    f"Found {len(unencrypted_queues)} unencrypted queues out of "
                    f"{len(encrypted_queues)+len(unencrypted_queues)} total queues"
                )
            else:
                pretty = f"All {len(encrypted_queues)} queues are properly encrypted at rest"

            region_results[region] = {
                "Passed": passed,
                "Result": pretty
            }

        # multi-region control
        self.control_results['CIS SQS.1'] = region_results
        return True

    def sqs_control_2(self, inputs=None) -> bool:
        """
        SQS Control 2 - Check if SQS queues are tagged
        """
        region_results = {}

        # Normalize specific_tags once
        raw_tags = ''
        try:
            cfg = self.config.input.get('config', {})
            raw_tags = cfg.get('requiredTagKeys', '')
        except Exception:
            raw_tags = ''
        if isinstance(raw_tags, str):
            raw_tags = raw_tags.strip()
            specific_tags = re.split(r'[,;\s]+', raw_tags) if raw_tags else []
        elif isinstance(raw_tags, list):
            specific_tags = raw_tags
        else:
            specific_tags = []

        # limit to 6
        specific_tags = specific_tags[:6]

        for client_name, client in self.clients.items():
            region = client.meta.region_name
            response = client.list_queues()

            tagged = []
            untagged = []
            missing = []

            if 'QueueUrls' in response:
                for url in response['QueueUrls']:
                    name = url.split('/')[-1]
                    tags = client.list_queue_tags(QueueUrl=url).get('Tags', {})
                    user = {k: v for k, v in tags.items() if not k.startswith('aws:')}
                    if specific_tags:
                        miss = [t for t in specific_tags if t not in user]
                        if miss:
                            missing.append({'name': name, 'url': url, 'current_tags': user, 'missing_tags': miss})
                        else:
                            tagged.append({'name': name, 'url': url, 'tags': user})
                    else:
                        (tagged if user else untagged).append({'name': name, 'url': url, **({'tags': user} if user else {})})
                total = len(tagged) + (len(missing) if specific_tags else len(untagged))
                # save per-region details
                self.collected_data[f"CIS SQS.2 - {region} - Tagged Queues"] = tagged
                self.collected_data[f"CIS SQS.2 - {region} - Untagged Queues"] = untagged
                self.collected_data[f"CIS SQS.2 - {region} - Queues Missing Required Tags"] = missing
                self.collected_data[f"CIS SQS.2 - {region} - Required Tags"] = specific_tags

                if not response['QueueUrls']:
                    ok, msg = True, "No SQS queues found in the account"
                elif specific_tags:
                    ok = not missing
                    msg = (f"All {len(tagged)} queues have the required tags"
                            if ok else
                            f"Found {len(missing)} queues missing required tags out of {total} total queues")
                else:
                    ok = not untagged
                    msg = (f"All {len(tagged)} queues have at least one user-defined tag"
                            if ok else
                            f"Found {len(untagged)} queues with no user-defined tags out of {total} total queues")
            else:
                ok, msg = True, "No SQS queues found in the account"
                # still record empty lists
                for kind in ("Tagged Queues", "Untagged Queues", "Queues Missing Required Tags"):
                    self.collected_data[f"CIS SQS.2 - {region} - {kind}"] = []
                self.collected_data[f"CIS SQS.2 - {region} - Required Tags"] = specific_tags

            region_results[region] = {"Passed": ok, "Result": msg}

        self.control_results['CIS SQS.2'] = region_results
        return True

    def sqs_control_3(self, inputs=None) -> bool:
        """
        SQS Control 3 - Check if SQS queues are publicly accessible
        """
        region_results = {}

        for client_name, client in self.clients.items():
            region = client.meta.region_name
            response = client.list_queues()

            public_queues = []
            private_queues = []

            if 'QueueUrls' in response:
                for queue_url in response['QueueUrls']:
                    queue_name = queue_url.split('/')[-1]
                    policy_resp = client.get_queue_attributes(
                        AttributeNames=['Policy'],
                        QueueUrl=queue_url
                    )
                    policy_str = policy_resp.get('Attributes', {}).get('Policy')
                    is_public = False

                    if policy_str:
                        policy = json.loads(policy_str)
                        for stmt in policy.get('Statement', []):
                            if stmt.get('Effect') == 'Allow':
                                princ = stmt.get('Principal', {})
                                if princ == "*" or princ.get('AWS') == "*":
                                    is_public = True
                                    break

                    if is_public:
                        public_queues.append({
                            'name': queue_name,
                            'url': queue_url,
                            'policy': policy_str
                        })
                    else:
                        private_queues.append({
                            'name': queue_name,
                            'url': queue_url,
                            'policy': policy_str
                        })

                self.collected_data[f"CIS SQS.3 - {region} - Public Queues"] = public_queues
                self.collected_data[f"CIS SQS.3 - {region} - Private Queues"] = private_queues

                if public_queues:
                    passed = False
                    pretty = (
                        f"Found {len(public_queues)} queues with public access "
                        f"out of {len(public_queues)+len(private_queues)} total queues"
                    )
                else:
                    passed = True
                    pretty = f"All {len(private_queues)} queues have private access policies"
            else:
                # no queues in this region
                self.collected_data[f"CIS SQS.3 - {region} - Public Queues"] = []
                self.collected_data[f"CIS SQS.3 - {region} - Private Queues"] = []
                passed = True
                pretty = "No SQS queues found in the account"

            region_results[region] = {"Passed": passed, "Result": pretty}

        self.control_results['CIS SQS.3'] = region_results
        return True

    def execute_all_controls(self, inputs=None) -> bool:
        passed_controls = sum(
            1 for c in self.control_results.values()
            if (
            isinstance(c, dict)
            and all(isinstance(v, dict) for v in c.values())
            and all(v.get("Passed") for v in c.values())
            ) or (c.get("Passed") is True)
        )
        total_controls = len(self.control_results)

        self.result.put_raw_extra_data("Summary", f"{passed_controls}/{total_controls} succeeded")

        for name, ctrl in self.control_results.items():
            # dump multi-region control and merge in per-region collected_data
            if isinstance(ctrl, dict) and all(isinstance(v, dict) for v in ctrl.values()):
                merged = {}
                for region, info in ctrl.items():
                    block = {
                        "Passed": info["Passed"],
                        "Result": info["Result"]
                    }
                    prefix = f"{name} - {region} - "
                    for k, v in self.collected_data.items():
                        if k.startswith(prefix):
                            field = k[len(prefix):]
                            block[field] = v
                    merged[region] = block
                self.result.put_raw_extra_data(name, merged)
                continue

            # single-block controls
            block = {
                "Passed": ctrl["Passed"],
                "Result": ctrl["Result"],
            }
            prefix = f"{name} - "
            for k, v in self.collected_data.items():
                if k.startswith(prefix):
                    field = k[len(prefix):]
                    block[field] = v
            self.result.put_raw_extra_data(name, block)

        if total_controls == 0:
            self.result.integer_result = 2
            self.result.pretty_result = "Credential error: AWS credentials are missing or invalid"
        else:
            self.result.integer_result = 0 if passed_controls == total_controls else 1
            self.result.pretty_result = "The probe executed successfully!"

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
                forward=self.sqs_control_1,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.sqs_control_2,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.sqs_control_3,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.execute_all_controls,
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
