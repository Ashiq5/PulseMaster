import json
import os
import pathlib
import subprocess
import requests
import logging
import fileinput
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from PulseMaster.settings import LOCAL, BASE_ZONE, SUB_ZONE

if LOCAL:
    base_dir = '/home/ubuntu/standalones/bind-test/'
else:
    base_dir = '/etc/bind/'

logging.basicConfig(filename='Outer_updates/logs/log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG)

logging.info("Start")

base_domain = 'cashcash.app'
base_zone_fn = 'db.' + base_domain
signed_base_zone_fn = base_zone_fn + '.signed'
base_zone_ip = "54.92.207.5"
sub_zone_ip = "3.237.179.78"
key_map = {}
key_generation_commands_in_base_zone = {
    "zsk": "dnssec-keygen -a RSASHA256 -b 2048 -K /etc/bind/zones/ -n ZONE cashcash.app",
    "ksk": "sudo dnssec-keygen -f KSK -a RSASHA256 -b 4096 -K /etc/bind/zones/ -n ZONE cashcash.app"
}
base_zone_keys = {
    "zsk": "/etc/bind/zones/Kcashcash.app.+008+61375",
    "ksk": "/etc/bind/zones/Kcashcash.app.+008+41837"
}
needs_base_zone_update = {}


def _replace_in_file(file_path, search_text, new_line):
    found = False
    with fileinput.input(file_path, inplace=True) as file:
        for line in file:
            if search_text in line:
                found = True
                print(new_line, end='')
            else:
                print(line, end='')
    if not found:
        with open(file_path, 'a') as file:
            file.write('\n' + new_line)


def _return_zone_file_content(**kwargs):
    zone_domain = kwargs['zone_domain']
    content = """;
; BIND data file for local loopback interface
;
"""
    content += "$ORIGIN  " + zone_domain + ".\n"
    content += "$TTL  " + str(int(kwargs['ttl']) * 60) + "\n"
    content += "@ IN  SOA ns1." + zone_domain + ". admin." + base_domain + ". (\n"
    content += "            " + str(kwargs['serial']) + "   ; Serial\n"
    content += "            " + str(kwargs['refresh']) + "   ; Refresh\n"
    content += "            " + str(kwargs['retry']) + "   ; Retry\n"
    content += "            " + str(kwargs['expire']) + "   ; Expire\n"
    content += "            " + str(int(kwargs['ttl']) * 60) + ")   ; Negative Cache TTL\n\n"

    content += ";Name Servers\n"
    content += "      IN  NS  ns1." + zone_domain + ".\n"
    content += "      IN  NS  ns2." + zone_domain + ".\n"
    content += "\n\n"

    content += ";Name Server IPs\n"
    content += "ns1           IN      A       " + sub_zone_ip + "\n"
    content += "ns2           IN      A       " + sub_zone_ip + "\n"
    content += "\n\n"

    content += "; Other records\n"
    # content += "*" + "             IN      A       " + kwargs['wildcard_ip'] + "\n\n"

    return content


def _execute_bash(cmd):
    print('Command:', cmd)
    return subprocess.run(cmd, shell=True, capture_output=True)


def _execute_bash_v2(cmd):
    print('Command_v2:', cmd)
    p = subprocess.run(cmd, shell=True, capture_output=True)
    logging.debug(cmd + " " + p.stdout.decode() + " " + p.stderr.decode())


def _load_key_map():
    for dirs in os.listdir(base_dir + 'zones/'):
        try:
            bucket_id = dirs.split('.')[0]
            if os.path.isdir(base_dir + 'zones/' + dirs + '/'):
                for file in os.listdir(base_dir + 'zones/' + dirs + '/'):
                    if '.key' in file:
                        lines = open(base_dir + 'zones/' + dirs + '/' + file).readlines()
                        if 'key-signing' in lines[0]:
                            key_map['ksk-' + bucket_id] = file[:-4]
                        elif 'zone-signing' in lines[0]:
                            key_map['zsk-' + bucket_id] = file[:-4]
        except Exception as e:
            continue


def _hard_refresh():
    try:
        _execute_bash_v2("cp " + base_dir + "named.conf.local.basic " + base_dir + "named.conf.local")
        for dirs in os.listdir(base_dir + 'zones/'):
            if os.path.isdir(base_dir + 'zones/' + dirs + '/'):
                _execute_bash_v2("rm -r " + base_dir + 'zones/' + dirs + '/')
        _reload_bind()
    except Exception as e:
        raise e


def _call_is_resigned_api(bucket_id):
    url = "http://" + sub_zone_ip + ':8080/is-being-resigned/?bucket_id=' + bucket_id
    header = {
        "Content-Type": "application/json",
    }
    res = requests.get(url, headers=header)
    if res.status_code != 200:
        raise Exception("resigning api resulted in error: ")
    return Response({'success': True}, status=status.HTTP_200_OK)


def _call_sign_api(bucket_id, placeholder_ip, validity):
    url = "http://" + sub_zone_ip + ':8080/sign-a-subzone/?bucket_id=' + bucket_id + '&signature_validity=' + validity \
          + "&ip=" + placeholder_ip
    header = {
        "Content-Type": "application/json",
    }
    res = requests.get(url, headers=header)
    if res.status_code != 200:
        raise Exception("signing resulted in error")
    return Response({'success': True}, status=status.HTTP_200_OK)


def _reload_bind():
    # _execute_bash_v2("rndc reload")
    _execute_bash_v2("service bind9 reload")


class IsResigned(APIView):
    def get(self, request):
        kwargs = request.GET.dict()
        bucket_id = kwargs['bucket_id']

        global needs_base_zone_update
        needs_base_zone_update[bucket_id] = False
        return Response({'success': True}, status=status.HTTP_200_OK)


class Refresh(APIView):
    def get(self, request):
        if BASE_ZONE:
            return Response({'success': False, 'error': str("Should not be applied in the base zone")}, status=status.HTTP_400_BAD_REQUEST)
        try:
            _hard_refresh()
            url = "http://" + base_zone_ip + ':8080/refresh-base-zone/'
            header = {
                "Content-Type": "application/json",
            }
            res = requests.get(url, headers=header)
            if res.status_code != 200:
                # TODO: extract error string
                raise Exception("Base Zone refresh resulted in error: ")
            return Response({'success': True}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class InitializeSubZones(APIView):
    def get(self, request):
        """
            :param request:
            ttl: in minutes
            ip: placeholder
            buckets: int
            offset: int
            :return:
            """
        if BASE_ZONE:
            return Response({'success': False, 'error': str("Should not be applied in the base zone")},
                            status=status.HTTP_400_BAD_REQUEST)
        global needs_base_zone_update
        kwargs = request.GET.dict()
        print(kwargs)
        ttl = kwargs['ttl']
        buckets = kwargs['buckets']
        offset = int(kwargs.get('offset', '0'))

        """
        1. create # zone files for # of buckets
        2. run dnssec-keygen for zsk and ksk
        3. run for loop to include DNSKEYs in the zone file
        4. upload dnskey as a ds record to the base zone and resign the base zone (not mandatory)
        5. reload bind
        """

        try:
            _hard_refresh()
            url = "http://" + base_zone_ip + ':8080/refresh-base-zone/'
            header = {
                "Content-Type": "application/json",
            }
            res = requests.get(url, headers=header)
            if res.status_code != 200:
                # TODO: extract error string
                raise Exception("Base Zone refresh resulted in error: ")
            _execute_bash_v2('cp ' + base_dir + 'named.conf.local ' + base_dir + 'named.conf.local.bk')
            # 1. create # zone files for # of buckets
            for i in range(1 + offset, int(buckets) + 1 + offset):
                needs_base_zone_update[str(i)] = True
                zone_domain = str(i) + '.' + base_domain
                zone_fn = "db." + zone_domain
                pathlib.Path(base_dir + 'zones/' + zone_domain).mkdir(parents=True, exist_ok=True)
                f = open(base_dir + 'zones/' + zone_domain + '/' + zone_fn, 'w')
                zone_file = _return_zone_file_content(serial=1, refresh=604800, retry=86400, expire=2419200,
                                                      negative_cache_ttl=604800, ttl=ttl,
                                                      ns1_ip=sub_zone_ip, ns2_ip=sub_zone_ip,
                                                      bucket_id=i, wildcard_ip="10.0.0.1", zone_domain=zone_domain)
                f.write(zone_file)

                # 2. run dnssec-keygen for zsk and ksk and save the name
                p = _execute_bash("dnssec-keygen -a RSASHA256 -b 2048" + " -K " + base_dir + 'zones/' +
                                  zone_domain + '/' + " -n ZONE " + zone_domain)
                stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
                found = False
                for j in stdout:
                    if base_domain in j:
                        key_map['zsk-' + str(i)] = j.strip()
                        found = True
                if not found:
                    raise Exception("ZS Key not created: " + "\n".join(stdout))

                p = _execute_bash("dnssec-keygen -f KSK -a RSASHA256 -b 4096" + " -K " + base_dir + 'zones/' +
                                  zone_domain + '/' + " -n ZONE " + zone_domain)
                stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
                found = False
                for j in stdout:
                    if base_domain in j:
                        key_map['ksk-' + str(i)] = j.strip()
                        found = True
                if not found:
                    raise Exception("KS Key not created: " + "\n".join(stdout))

                # 3. run for loop to include DNSKEYs in the zone file
                for key_file in os.listdir(base_dir + 'zones/' + zone_domain + '/'):
                    if '.key' in key_file and zone_domain in key_file:
                        f.write('$INCLUDE ' + base_dir + 'zones/' + zone_domain + '/' + key_file + "\n")
                f.close()

                # 4. update the zone in named.conf.local (unsigned version)
                local_bind_file = open(base_dir + 'named.conf.local', 'a')
                local = '\nzone "' + zone_domain + '" {\n\
                type master;\n\
                file "' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '";\n\
};\n'
                local_bind_file.write(local)
                local_bind_file.close()

                _call_sign_api(str(i), "10.0.0.1", str(30))

                # remove the backup file on success
                # _execute_bash_v2("rm " + base_dir + "named.conf.local.bk")
        except Exception as e:
            # revert all the steps done before
            print('Exception in init', e)
            logging.debug('Exception in init' + str(e))
            _hard_refresh()
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # 5. reload bind
        _reload_bind()
        logging.info("init done")
        return Response({'success': True}, status=status.HTTP_200_OK)


class SignASubZone(APIView):
    def get(self, request):
        """
            bucket_id: int
            ip: webserver address
            signature_validity: in minutes
            :return:
            """
        if BASE_ZONE:
            return Response({'success': False, 'error': str("Should not be applied in the base zone")},
                            status=status.HTTP_400_BAD_REQUEST)
        kwargs = request.GET.dict()
        print('KWARGS', kwargs)
        validity = kwargs['signature_validity']
        bucket_id = kwargs['bucket_id']
        ip = kwargs['ip']

        """
        1. update the placeholder ip
        2. produce the signed zone file
        3. load the signed zone in named.conf.local
        4. reload
        """
        _load_key_map()
        print('Key Map', len(key_map))
        flag = 1
        zone_domain = kwargs['bucket_id'] + '.' + base_domain
        zone_fn = "db." + zone_domain
        signed_zone_fn = zone_fn + ".signed"
        try:
            # 1. update the placeholder ip
            _execute_bash_v2('cp ' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + ' ' + base_dir + 'zones/' +
                             zone_domain + '/' + zone_fn + '.bk')
            if os.path.exists(base_dir + 'zones/' + zone_domain + '/' + zone_fn + '.signed'):
                _execute_bash_v2('cp ' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '.signed ' + base_dir +
                                 'zones/' + zone_domain + '/' + zone_fn + '.signed.bk')

            file_path = base_dir + 'zones/' + zone_domain + '/' + zone_fn
            _replace_in_file(file_path, "*             IN      A       ", "*             IN      A       " + ip)
            logging.info("subzone " + bucket_id + " 's zone file properly changed")

            # 2. produce the signed zone file
            p = _execute_bash(
                'dnssec-signzone -N INCREMENT -o ' + zone_domain + ' -e now+' +
                str(int(validity) * 60) + ' -k ' + base_dir + 'zones/' + zone_domain + '/' +
                key_map['ksk-' + bucket_id] + '.key' + ' -t ' + base_dir + 'zones/' + zone_domain + '/' +
                zone_fn + ' ' + base_dir + 'zones/' + zone_domain + '/' + key_map['zsk-' + bucket_id] + '.private'
            )
            stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
            signed = False
            for j in stdout:
                if 'Zone fully signed:' in j:
                    signed = True
            print(stdout)
            if not signed:
                raise Exception("Signing resulted in failure: " + "\n".join(stdout))
            logging.info("subzone " + bucket_id + " properly signed")

            # 3. upload dnskey as a ds record to the base zone and resign the base zone
            flag = 2
            global needs_base_zone_update
            print('needs', bucket_id, needs_base_zone_update)
            if needs_base_zone_update[bucket_id]:
                with open('dsset-' + zone_domain + '.') as f1:
                    lines = f1.readlines()
                    ds_rr = lines[0].strip()

                    url_for_post = "http://" + base_zone_ip + ':8080/update-base-zone/'
                    url_for_get = url_for_post + '?bucket_id=' + bucket_id + '&ds_record=' + ds_rr
                    header = {
                        "Content-Type": "application/json",
                    }
                    res = requests.get(url_for_get, headers=header)
                    if res.status_code != 200:
                        # TODO: extract error string
                        raise Exception("Base Zone modification resulted in error: ")
                logging.info("base zone updated properly")

                # 4. load the signed zone in named.conf.local
                flag = 3
                _execute_bash_v2('cp ' + base_dir + 'named.conf.local ' + base_dir + 'named.conf.local.bk')

                file_path = base_dir + 'named.conf.local'
                _replace_in_file(file_path, 'file "' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '',
                                 '                file "' + base_dir + 'zones/' + zone_domain + '/' + signed_zone_fn + '";\n')
                logging.info("named.conf.local updated")

            # 5. reload
            flag = 4
            _reload_bind()
            return Response({'success': True}, status=status.HTTP_200_OK)
        except Exception as e:
            print('Exception in signing', e)
            logging.debug('Exception in signing, ' + str(e))
            if flag == 1 or flag == 3:
                _execute_bash_v2('cp ' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '.bk ' + base_dir + 'zones/' +
                                 zone_domain + '/' + zone_fn)
                if os.path.exists(base_dir + 'zones/' + zone_domain + '/' + zone_fn + '.signed.bk'):
                    _execute_bash_v2(
                        'cp ' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '.signed.bk ' + base_dir + 'zones/' +
                        zone_domain + '/' + zone_fn + '.signed')
                if flag == 3:
                    _execute_bash_v2("cp " + base_dir + "named.conf.local.bk " + base_dir + "named.conf.local")
            # 5. reload
            _reload_bind()
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class RefreshBaseZone(APIView):
    def get(self, request):
        if SUB_ZONE:
            return Response({'success': False, 'error': str("Should not be applied in the sub zone")},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            _execute_bash_v2('cp ' + base_dir + 'zones/' + base_zone_fn + '.basic ' + base_dir + 'zones/' + base_zone_fn)
            _execute_bash_v2('cp ' + base_dir + 'zones/' + base_zone_fn + '.signed.basic ' +
                             base_dir + 'zones/' + base_zone_fn + '.signed')
            _reload_bind()
            return Response({'success': True}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UpdateBaseZone(APIView):
    def get(self, request):
        if SUB_ZONE:
            return Response({'success': False, 'error': str("Should not be applied in the sub zone")},
                            status=status.HTTP_400_BAD_REQUEST)
        kwargs = request.GET.dict()
        bucket_id = kwargs['bucket_id']
        ds_record = kwargs['ds_record'].replace('%20', ' ').replace('%09', ' ')
        print("ds record", ds_record, "bucket_id", bucket_id)
        try:
            _execute_bash_v2('cp ' + base_dir + 'zones/' + base_zone_fn + ' ' + base_dir + 'zones/' + base_zone_fn + '.bk')
            _execute_bash_v2(
                'cp ' + base_dir + 'zones/' + signed_base_zone_fn + ' ' + base_dir + 'zones/' + signed_base_zone_fn +
                '.bk')

            f2 = open(base_dir + 'zones/' + base_zone_fn)
            lines = f2.readlines()
            f2.close()

            ds_rr_value = ds_record.split('DS')[1].strip()
            lines.append(bucket_id + '       IN       DS      ' + ds_rr_value + '\n')
            lines.append(bucket_id + '       IN       NS      ns1.' + bucket_id + '.cashcash.app.\n')
            lines.append(bucket_id + '       IN       NS      ns2.' + bucket_id + '.cashcash.app.\n')
            lines.append('ns1.' + bucket_id + '    IN      A       ' + sub_zone_ip + '\n')
            lines.append('ns2.' + bucket_id + '    IN      A       ' + sub_zone_ip + '\n')

            f2 = open(base_dir + 'zones/' + base_zone_fn, 'w')
            f2.write("".join(lines))
            f2.close()

            # resign the base zone
            p = _execute_bash("dnssec-signzone -k " + base_zone_keys["ksk"] + '.key' +
                              " -N INCREMENT -o cashcash.app  -t /etc/bind/zones/db.cashcash.app"
                              " " + base_zone_keys["zsk"] + '.private')
            stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
            print(p)
            signed = False
            for j in stdout:
                if 'Zone fully signed:' in j:
                    signed = True
            if not signed:
                raise Exception("Signing resulted in failure: " + "\n".join(stdout))
            _reload_bind()
            _call_is_resigned_api(bucket_id)
            return Response({'success': True}, status=status.HTTP_200_OK)
        except Exception as e:
            print('Exception in update base zone', e)
            _execute_bash_v2('cp ' + base_dir + 'zones/' + base_zone_fn + '.bk ' + base_dir + 'zones/' + base_zone_fn)
            _execute_bash_v2(
                'cp ' + base_dir + 'zones/' + signed_base_zone_fn + '.bk ' + base_dir + 'zones/' + signed_base_zone_fn)
            _reload_bind()
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
