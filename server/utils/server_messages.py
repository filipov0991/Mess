from datetime import datetime as dt


class JimServerMessage:
    def probe(self, sender, status="Are you there?"):
        data = {
            "action": "probe",
            "time": dt.now().timestamp(),
            "type": "status",
            "user": {
                "account_name": sender,
                "status": status
            }
        }
        return data

    def response(self, code=None, error=None):
        _data = {
            'action': 'response',
            'code': code,
            'time': dt.now().timestamp(),
            'error': error
        }
        return _data
