import os
from collections import defaultdict
import datetime


def does_exp_id_match(line, exp_id_list):
    prefix = ".live_recpronew_{}_".format(exp_threshold_for_this_server)
    try:
        if prefix not in line:
            return False, None
        st_index = line.find(prefix)
        sub = line[st_index + 1:]
        sub = sub.split(".")[0]
        return True, sub
    except Exception:
        return False, None


def is_event_log(log):
    for e in event_strings:
        if e in log:
            return e
    return None


def parse_bind_line_and_build_meta(line):
    l = line.strip()
    segments = l.split(" ")
    time = segments[0] + "-" + segments[1]
    resolver_ip = segments[5]
    resolver_ip = resolver_ip[: resolver_ip.rfind("#")]
    url = segments[8]
    datetime_object = datetime.datetime.strptime(time, '%d-%b-%Y-%H:%M:%S.%f')
    meta = {"date": datetime_object, "url": url, "resolver_ip": resolver_ip}
    return meta


def parse_apache_line_and_build_meta(line):
    l = line.strip()
    segments = l.split(" ")
    time = segments[4]
    client_ip = segments[0]
    url = segments[-1]
    time = time[1:len(time) - 1]
    time = time.split()[0]
    datetime_object = datetime.datetime.strptime(time, '%d/%b/%Y:%H:%M:%S')

    meta = {"date": datetime_object, "url": url, "client_ip": client_ip}
    return meta


def parse_bind_apache_logs(exp_id_list, files, is_bind=True):
    ans_dict = defaultdict(lambda: dict())
    tot_files = len(files)
    index = 0

    for file in files:
        index += 1
        with open(file) as FileObj:
            for line in FileObj:
                try:
                    if url_live not in line:
                        continue
                    is_exp_id_present, exp_id = does_exp_id_match(line, [])
                    if not is_exp_id_present:
                        continue
                    d = ans_dict[exp_id]

                    if "req" not in d:
                        d["req"] = {}
                    if is_bind:
                        if line.startswith("client"):
                            continue
                    if is_bind:
                        meta = parse_bind_line_and_build_meta(line=line)
                    else:
                        meta = parse_apache_line_and_build_meta(line=line)

                    url = meta["url"]
                    is_event = is_event_log(url)
                    if is_event:
                        if is_event not in d:
                            d[is_event] = []
                        d[is_event].append(meta)
                    else:
                        identifier = str(url.split(".")[0])
                        if identifier not in d["req"]:
                            d["req"][identifier] = list()
                        d["req"][identifier].append(meta)
                        if is_bind:
                            req_id_to_resolvers[identifier].add(meta["resolver_ip"])
                        else:
                            req_id_to_client_ips[identifier].add(meta["client_ip"])
                except Exception as e:
                    print('parse bind apache logs ', e)

        print("*** Done with parsing Bind file {}".format(file))
        print("Done with isbind {}, {}/{}".format(is_bind, index, tot_files))

    return ans_dict


def parse_logs_together(allowed_exp_ids):
    bind_dir_par = BASE_URL_BIND_APACHE + 'parent/'
    bind_files_par = [bind_dir_par + f for f in os.listdir(bind_dir_par)
                      if os.path.isfile(os.path.join(bind_dir_par, f)) and
                      '.gz' not in f]

    bind_dir_chi = BASE_URL_BIND_APACHE + 'parent/'
    bind_files_chi = [bind_dir_chi + f for f in os.listdir(bind_dir_chi)
                      if os.path.isfile(os.path.join(bind_dir_chi, f)) and
                      '.gz' not in f]

    apache_logs_phase_1_dir = BASE_URL_BIND_APACHE + 'apache1/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in os.listdir(apache_logs_phase_1_dir) if
                           os.path.isfile(
                               os.path.join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = BASE_URL_BIND_APACHE + 'apache2/'
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in os.listdir(apache_logs_phase_2_dir) if
                           os.path.isfile(
                               os.path.join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    bind_info_global_par = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files_par, is_bind=True)
    bind_info_global_chi = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files_chi, is_bind=True)
    apache_info_one_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_1,
                                                    is_bind=False)
    apache_info_two_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_2,
                                                    is_bind=False)

    return bind_info_global_par, bind_info_global_chi, apache_info_one_global, apache_info_two_global


def master_calc():
    bind_info_global_par, bind_info_global_chi, apache_info_one_global, apache_info_two_global = parse_logs_together(allowed_exp_ids=[])
    print(bind_info_global_par, bind_info_global_chi, apache_info_one_global, apache_info_two_global)
    print("Done with parsing bind/apache logs")


if __name__ == "__main__":
    BASE_URL_BIND_APACHE = "/net/data/dns-ttl/"
    url_live = 'ttlexp.exp.net-measurement.net'
    instance_id = int(os.environ['instance_id'])
    exp_threshold_list = [43, 49, 55, 58]
    exp_threshold_for_this_server = exp_threshold_list[instance_id - 1]
    event_strings = ["phase1-start", "phase1-end", "sleep-end", "phase2-end"]
    req_id_to_resolvers = defaultdict(lambda: set())
    req_id_to_client_ips = defaultdict(lambda: set())



