#! /usr/bin/env python3

import boto3 # type: ignore
import typing
import datetime
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
        region = config.get('region') 

        assert access_key_id is not None, "AWS Access Key ID is missing"
        assert secret_access_key is not None, "AWS Secret Access Key is missing"
        
        self.client = boto3.client(
            'inspector2',
            aws_access_key_id = access_key_id,
            aws_secret_access_key = secret_access_key,
            region_name = region or 'eu-central-1'
        )

        self.client.list_members(maxResults=1)

        return True

    def inspector_check_1(self, inputs=None) -> bool:
        """
        Inspector.1 - Amazon Inspector EC2 scanning should be enabled
        """
        response = self.client.batch_get_account_status()
        current_account = response.get('accounts', [{}])[0]
        ec2_status = current_account.get('resourceState', {}).get('ec2', {}).get('status')
        admin_enabled = ec2_status == 'ENABLED'

        members = self.client.list_members().get('members', [])
        compliant, non_compliant = [], []

        if not members:
            acct = current_account.get('accountId', 'current')
            (compliant if admin_enabled else non_compliant).append(acct)
            pretty = (
                "Amazon Inspector EC2 scanning is properly enabled"
                if admin_enabled else
                "Amazon Inspector EC2 scanning is not enabled"
            )
        else:
            # delegated admin + members
            root_id = current_account.get('accountId', 'admin')
            (compliant if admin_enabled else non_compliant).append(root_id)

            for m in members:
                sid = m.get('accountId')
                st = m.get('resourceState', {}).get('ec2', {}).get('status')
                rel = m.get('relationshipStatus')
                if st == 'ENABLED' or rel == 'SUSPENDED':
                    compliant.append(sid)
                else:
                    non_compliant.append(sid)

            if non_compliant:
                pretty = (
                    f"Found {len(non_compliant)} accounts without Inspector EC2 scanning "
                    f"enabled out of {len(compliant)+len(non_compliant)} total accounts"
                )
            else:
                pretty = f"Amazon Inspector EC2 scanning is enabled for all {len(compliant)} accounts"

        passed = len(non_compliant) == 0
        self.control_results["CIS Inspector.1"] = {
            "Passed": passed,
            "Result": pretty
        }
        return True

    def inspector_check_2(self, inputs=None) -> bool:
        """
        Inspector.2 - Amazon Inspector ECR scanning should be enabled
        """
        response = self.client.batch_get_account_status()
        current_account = response.get('accounts', [{}])[0]
        ecr_status = current_account.get('resourceState', {}).get('ecr', {}).get('status')
        admin_enabled = ecr_status == 'ENABLED'

        members = self.client.list_members().get('members', [])
        compliant, non_compliant = [], []

        if not members:
            acct = current_account.get('accountId', 'current')
            (compliant if admin_enabled else non_compliant).append(acct)
            pretty = (
                "Amazon Inspector ECR scanning is properly enabled"
                if admin_enabled else
                "Amazon Inspector ECR scanning is not enabled"
            )
        else:
            # delegated admin + members
            root_id = current_account.get('accountId', 'admin')
            (compliant if admin_enabled else non_compliant).append(root_id)

            for m in members:
                sid = m.get('accountId')
                st = m.get('resourceState', {}).get('ecr', {}).get('status')
                rel = m.get('relationshipStatus')
                if st == 'ENABLED' or rel == 'SUSPENDED':
                    compliant.append(sid)
                else:
                    non_compliant.append(sid)

            if non_compliant:
                pretty = (
                    f"Found {len(non_compliant)} accounts without Inspector ECR scanning "
                    f"enabled out of {len(compliant)+len(non_compliant)} total accounts"
                )
            else:
                pretty = f"Amazon Inspector ECR scanning is enabled for all {len(compliant)} accounts"

        passed = len(non_compliant) == 0
        self.control_results["CIS Inspector.2"] = {
            "Passed": passed,
            "Result": pretty
        }
        return True

    def inspector_check_3(self, inputs=None) -> bool:
        """
        Inspector.3 - Amazon Inspector Lambda code scanning should be enabled
        """
        response = self.client.batch_get_account_status()
        current_account = response.get('accounts', [{}])[0]
        lambda_code_status = current_account.get('resourceState', {}).get('lambdaCode', {}).get('status')
        admin_enabled = lambda_code_status == 'ENABLED'

        members = self.client.list_members().get('members', [])
        compliant, non_compliant = [], []

        if not members:
            acct = current_account.get('accountId', 'current')
            (compliant if admin_enabled else non_compliant).append(acct)
            pretty = (
                "Amazon Inspector Lambda code scanning is properly enabled"
                if admin_enabled else
                "Amazon Inspector Lambda code scanning is not enabled"
            )
        else:
            # delegated admin + members
            root_id = current_account.get('accountId', 'admin')
            (compliant if admin_enabled else non_compliant).append(root_id)

            for m in members:
                sid = m.get('accountId')
                st = m.get('resourceState', {}).get('lambdaCode', {}).get('status')
                rel = m.get('relationshipStatus')
                if st == 'ENABLED' or rel == 'SUSPENDED':
                    compliant.append(sid)
                else:
                    non_compliant.append(sid)

            if non_compliant:
                pretty = (
                    f"Found {len(non_compliant)} accounts without Inspector Lambda code scanning "
                    f"enabled out of {len(compliant)+len(non_compliant)} total accounts"
                )
            else:
                pretty = f"Amazon Inspector Lambda code scanning is enabled for all {len(compliant)} accounts"

        passed = len(non_compliant) == 0
        self.control_results["CIS Inspector.3"] = {
            "Passed": passed,
            "Result": pretty
        }
        return True

    def inspector_check_4(self, inputs=None) -> bool:
        """
        Inspector.4 - Amazon Inspector Lambda standard scanning should be enabled
        """
        response = self.client.batch_get_account_status()
        current_account = response.get('accounts', [{}])[0]
        lambda_status = current_account.get('resourceState', {}).get('lambda', {}).get('status')
        admin_enabled = lambda_status == 'ENABLED'

        members = self.client.list_members().get('members', [])
        compliant, non_compliant = [], []

        if not members:
            acct = current_account.get('accountId', 'current')
            (compliant if admin_enabled else non_compliant).append(acct)
            pretty = (
                "Amazon Inspector Lambda standard scanning is properly enabled"
                if admin_enabled else
                "Amazon Inspector Lambda standard scanning is not enabled"
            )
        else:
            # delegated admin + members
            root_id = current_account.get('accountId', 'admin')
            (compliant if admin_enabled else non_compliant).append(root_id)

            for m in members:
                sid = m.get('accountId')
                st = m.get('resourceState', {}).get('lambda', {}).get('status')
                rel = m.get('relationshipStatus')
                if st == 'ENABLED' or rel == 'SUSPENDED':
                    compliant.append(sid)
                else:
                    non_compliant.append(sid)

            if non_compliant:
                pretty = (
                    f"Found {len(non_compliant)} accounts without Inspector Lambda standard scanning "
                    f"enabled out of {len(compliant)+len(non_compliant)} total accounts"
                )
            else:
                pretty = f"Amazon Inspector Lambda standard scanning is enabled for all {len(compliant)} accounts"

        passed = len(non_compliant) == 0
        self.control_results["CIS Inspector.4"] = {
            "Passed": passed,
            "Result": pretty
        }
        return True       
    
    def execute_all_controls(self, inputs=None) -> bool:
        passed_controls = sum(1 for c in self.control_results.values() if c["Passed"])
        total_controls = len(self.control_results)
        self.result.put_raw_extra_data("Summary", f"{passed_controls}/{total_controls} succeeded")

        for name, ctrl in self.control_results.items():
            if name == "CVE Scan":
                continue
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
        
        if passed_controls == 0:
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
                forward=self.inspector_check_1,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.inspector_check_2,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.inspector_check_3,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=Exception,
                        action=atom.OnExceptionActionForward.GO_ON,
                        result_producer=lambda e: result.Result(base_extra_data=result.Extradata(raw={'ExceptionRecovered': str(e)}))
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.inspector_check_4,
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