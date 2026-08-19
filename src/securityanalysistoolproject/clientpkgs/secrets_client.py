'''secrets module'''
import base64
from core.dbclient import SatDBClient


class SecretsClient(SatDBClient):
    '''secrets helper class'''

    def get_secret_scopes_list(self):
        '''list of scopes'''
        scopes_list = self.get('/secrets/scopes/list').get('scopes', [])
        return scopes_list

    def get_secrets(self, scope_list):
        '''get list of secrets (2 chamadas por scope, escopos em paralelo)'''
        from concurrent.futures import ThreadPoolExecutor

        def _one(iscope):
            out = []
            secrets_list = self.get('/secrets/list', {'scope': iscope['name']}).get('secrets', [])
            secrets_acl_list = self.get('/secrets/acls/list', {'scope': iscope['name']}).get('items', [])
            for isecret in secrets_list:
                isecret['scope'] = iscope
                isecret['acls'] = secrets_acl_list
                out.append(isecret)
            return out

        glob_secrets = []
        scope_list = list(scope_list)
        if not scope_list:
            return glob_secrets
        glob_secrets.extend(_one(scope_list[0]))  # aquece token em serie
        if len(scope_list) > 1:
            with ThreadPoolExecutor(max_workers=8) as pool:
                for out in pool.map(_one, scope_list[1:]):
                    glob_secrets.extend(out)
        return glob_secrets

    def get_secret_value(self, scope_name, secret_key):
        '''get value of secret'''
        ec_id = self.get_execution_context()
        cmd_set_value = f"value = dbutils.secrets.get(scope = '{scope_name}', key = '{secret_key}')"
        cmd_convert_b64 = "import base64; b64_value = base64.b64encode(value.encode('ascii'))"
        cmd_get_b64 = "print(str(b64_value.decode('ascii')))"   # b64_value.decode('ascii')
        _ = self.submit_command(ec_id, cmd_set_value)
        _ = self.submit_command(ec_id, cmd_convert_b64)
        results_get = self.submit_command(ec_id, cmd_get_b64)
        val = results_get.get('data')
        print(val)
        b64_value_decode = base64.b64decode(val).decode('ascii')
        return b64_value_decode
