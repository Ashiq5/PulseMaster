import os
import pathlib
import subprocess
import requests

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from PulseMaster.settings import LOCAL

if LOCAL:
    base_dir = '/home/ubuntu/standalones/bind-test/'
else:
    base_dir = '/etc/bind/'

base_domain = 'cashcash.app'
base_zone_fn = 'db.' + base_domain
signed_base_zone_fn = base_zone_fn + '.signed'
base_zone_ip = "54.92.207.5"
sub_zone_ip = "3.237.179.78"
key_map = {}

# TODOs:
"""
1. test with dig and dnsviz that everything is alright if no configuration breaks do happen
2. if exception occurs, check whether the backup file is getting created and moved properly
3. change os.system to subprocess.run
4. add proper logging
"""


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
    content += "            " + str(kwargs['negative_cache_ttl']) + ")   ; Negative Cache TTL\n\n"

    content += ";Name Servers\n"
    content += "      IN  NS  ns1." + zone_domain + ".\n"
    content += "      IN  NS  ns2." + zone_domain + ".\n"
    content += "\n\n"

    content += ";Name Server IPs\n"
    content += "ns1           IN      A       " + sub_zone_ip + "\n"
    content += "ns2           IN      A       " + sub_zone_ip + "\n"
    content += "\n\n"

    content += "; Other records\n"
    content += "*" + "             IN      A       " + kwargs['wildcard_ip'] + "\n\n"

    return content


def _execute_bash(cmd):
    print('Command:', cmd)
    return subprocess.run(cmd, shell=True, capture_output=True)


def _load_key_map():
    for dirs in os.listdir(base_dir + 'zones/'):
        try:
            bucket_id = dirs.split('.')[0]
            if os.path.isdir(dirs):
                for file in os.listdir(base_dir + 'zones/' + dirs + '/'):
                    if '.key' in file:
                        lines = open(file).readlines()
                        if 'key-signing' in lines[0]:
                            key_map['ksk-' + bucket_id] = file
                        elif 'zone-signing' in lines[0]:
                            key_map['zsk-' + bucket_id] = file
        except Exception as e:
            continue


class BindInitView(APIView):
    def get(self, request):
        """
            :param request:
            ttl: in minutes
            ip: placeholder
            buckets: int
            :return:
            """
        kwargs = request.GET.dict()
        print(kwargs)
        ttl = kwargs['ttl']
        ip = kwargs['ip']
        buckets = kwargs['buckets']

        """
        1. create # zone files for # of buckets
        2. run dnssec-keygen for zsk and ksk
        3. run for loop to include DNSKEYs in the zone file
        4. upload dnskey as a ds record to the base zone and resign the base zone (not mandatory)
        5. reload bind
        """

        try:
            os.system('cp ' + base_dir + 'named.conf.local ' + base_dir + 'named.conf.local.bk')
            # 1. create # zone files for # of buckets
            for i in range(1, int(buckets) + 1):
                zone_domain = str(i) + '.' + base_domain
                zone_fn = "db." + zone_domain
                pathlib.Path(base_dir + 'zones/' + zone_domain).mkdir(parents=True, exist_ok=True)
                f = open(base_dir + 'zones/' + zone_domain + '/' + zone_fn, 'w')
                zone_file = _return_zone_file_content(serial=1, refresh=604800, retry=86400, expire=2419200,
                                                      negative_cache_ttl=604800, ttl=ttl,
                                                      ns1_ip=sub_zone_ip, ns2_ip=sub_zone_ip,
                                                      bucket_id=i, wildcard_ip=ip, zone_domain=zone_domain)
                f.write(zone_file)

                # 2. run dnssec-keygen for zsk and ksk and save the name
                p = _execute_bash("dnssec-keygen -a NSEC3RSASHA1 -b 2048" + " -K " + base_dir + 'zones/' +
                                  zone_domain + '/' + " -n ZONE " + zone_domain)
                stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
                found = False
                for j in stdout:
                    if base_domain in j:
                        key_map['zsk-' + str(i)] = j.strip()
                        found = True
                if not found:
                    raise Exception("ZS Key not created: " + "\n".join(stdout))

                p = _execute_bash("dnssec-keygen -f KSK -a NSEC3RSASHA1 -b 4096" + " -K " + base_dir + 'zones/' +
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

                # 4. update the zone in named.conf.local (unsigned version)
                local_bind_file = open(base_dir + 'named.conf.local', 'a')
                local = '\nzone "' + zone_domain + '" {\n\
                type master;\n\
                file "' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '";\n\
};\n'
                local_bind_file.write(local)
                local_bind_file.close()

                # remove the backup file on success
                # os.system("rm " + base_dir + "named.conf.local.bk")

                f.close()
        except Exception as e:
            # revert all the steps done before
            print(e)
            os.system("mv " + base_dir + "named.conf.local.bk " + base_dir + "named.conf.local")
            for i in range(1, int(buckets) + 1):
                zone_domain = str(i) + '.' + base_domain
                if os.path.isdir(base_dir + 'zones/' + zone_domain):
                    os.system("rm -r " + base_dir + 'zones/' + zone_domain)
            # 5. reload bind
            os.system('service bind9 reload')
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # 5. reload bind
        os.system('service bind9 reload')
        return Response({'success': True}, status=status.HTTP_200_OK)


class BindUpdateView(APIView):
    def get(self, request):
        """
            bucket_id: int
            ip: webserver address
            signature_validity: in minutes
            :return:
            """

        kwargs = request.GET.dict()
        print(kwargs)
        validity = kwargs['signature_validity']
        bucket_id = kwargs['bucket_id']
        # ip = kwargs['ip']

        """
        1. produce the signed zone file
        2. load the signed zone in named.conf.local
        3. reload
        """
        _load_key_map()
        print(key_map)
        flag = 1
        try:
            zone_domain = kwargs['bucket_id'] + '.' + base_domain
            zone_fn = "db." + zone_domain
            signed_zone_fn = zone_fn + ".signed"

            # 1. produce the signed zone file
            p = _execute_bash(
                'dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o ' +
                zone_domain + ' -e now+' + str(int(validity) * 60) + ' -k ' + base_dir + 'zones/' + zone_domain + '/' +
                key_map['ksk-' + bucket_id] + '.key'
                + ' -t ' + base_dir + 'zones/' + zone_domain + '/' +
                zone_fn + ' ' + base_dir + 'zones/' + zone_domain + '/' + key_map['zsk-' + bucket_id] + '.private'
            )
            stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
            signed = False
            for j in stdout:
                if 'Zone fully signed:' in j:
                    signed = True
            if not signed:
                raise Exception("Signing resulted in failure: " + "\n".join(stdout))

            # 2. upload dnskey as a ds record to the base zone and resign the base zone
            flag = 2
            with open('dsset-' + zone_domain + '.') as f1:
                lines = f1.readlines()
                ds_rr = lines[0].strip()
                url = "http://" + base_zone_ip + ':8080/update-base-zone/?bucket-id=' + bucket_id + \
                      '&ds_record=' + ds_rr
                header = {
                    "Content-Type": "application/json",
                }

                res = requests.get(url, headers=header)
                if res.status_code != 200:
                    # TODO: extract error string
                    raise Exception("Base Zone modification resulted in error: ")

            # 3. load the signed zone in named.conf.local
            flag = 3
            os.system('cp ' + base_dir + 'named.conf.local ' + base_dir + 'named.conf.local.bk')
            local_bind_file = open(base_dir + 'named.conf.local', 'r')
            lines = local_bind_file.readlines()
            for ind, line in enumerate(lines):
                if 'file "' + base_dir + 'zones/' + zone_domain + '/' + zone_fn + '' in line:
                    x = '             file "' + base_dir + 'zones/' + zone_domain + '/' + signed_zone_fn + '";\n'
                    lines[ind] = x
            local_bind_file.close()

            local_bind_file = open(base_dir + 'named.conf.local', 'w')
            local_bind_file.write("".join(lines))
            local_bind_file.close()

            # 4. reload
            flag = 4
            os.system('service bind9 reload')
            return Response({'success': True}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            if flag == 3:
                os.system("mv " + base_dir + "named.conf.local.bk " + base_dir + "named.conf.local")
            # 4. reload
            os.system('service bind9 reload')
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UpdateBaseZoneFile(APIView):
    def get(self, request):
        kwargs = request.GET.dict()
        print(kwargs)
        bucket_id = kwargs['bucket_id']
        ds_record = kwargs['ds_record']

        try:
            os.system('cp ' + base_dir + 'zones/' + base_zone_fn + ' ' + base_dir + 'zones/' + base_zone_fn + '.bk')
            os.system(
                'cp ' + base_dir + 'zones/' + signed_base_zone_fn + ' ' + base_dir + 'zones/' + signed_base_zone_fn + '.bk')
            with open(base_dir + 'zones/' + base_zone_fn, 'a') as f2:
                f2.write('\n')
                ds_rr_value = ds_record.split('DS')[1].strip()
                f2.write(bucket_id + '       IN      DS      ' + ds_rr_value + '\n')
                f2.write(bucket_id + '       IN      NS      ns1.' + bucket_id + '.cashcash.app.\n')
                f2.write(bucket_id + '       IN      NS      ns2.' + bucket_id + '.cashcash.app.\n')
                f2.write('ns1.' + bucket_id + '    IN      A      ' + sub_zone_ip + '\n')
                f2.write('ns2.' + bucket_id + '    IN      A      ' + sub_zone_ip + '\n')

                # resign the base zone
                p = _execute_bash("sudo dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) "
                                  "-k /etc/bind/zones/Kcashcash.app.+007+48166.key -N INCREMENT -o cashcash.app  "
                                  "-t /etc/bind/zones/db.cashcash.app /etc/bind/zones/Kcashcash.app.+007+53958.private")
                stdout = p.stdout.decode().split('\n') + p.stderr.decode().split('\n')
                signed = False
                for j in stdout:
                    if 'Zone fully signed:' in j:
                        signed = True
                if not signed:
                    raise Exception("Signing resulted in failure: " + "\n".join(stdout))
                os.system('service bind9 reload')
                return Response({'success': True}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            os.system('mv ' + base_dir + 'zones/' + base_zone_fn + '.bk ' + base_dir + 'zones/' + base_zone_fn)
            os.system(
                'mv ' + base_dir + 'zones/' + signed_base_zone_fn + '.bk ' + base_dir + 'zones/' + signed_base_zone_fn)
            os.system('service bind9 reload')
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
