import avro.schema
from avro.datafile import DataFileReader, DataFileWriter
from avro.io import DatumReader, DatumWriter
import numpy as np
import os
import json


dir = "/home/ashiq/PulseMaster/openintel-alexa1m-20220516/"
all_ttls = []
arr = os.listdir(dir)
a = 1

for f in arr:
    reader = DataFileReader(
        open(dir + "{}".format(f), "rb"), DatumReader())
    for user in reader:
        # print(user)
        if user['response_ttl']:
            all_ttls.append(user['response_ttl'])
            if len(all_ttls) % 10000 == 0:
                print(len(all_ttls))
                # break
    reader.close()
    # break

print(all_ttls)

# sort data
x = np.sort(all_ttls)
print(x)

# calculate CDF values
# y = np.arange(1, len(all_ttls) + 1)
y = 1. * np.arange(len(all_ttls)) / (len(all_ttls) - 1)
print(y)

with open('temp/cdf-ttl-openintel', 'w') as f:
    for i, j in zip(x, y):
        f.write(str(i) + ',' + str(j) + '\n')

# plot CDF
# plt.plot(x, y)
# plt.show()

# with open("info_cdf.json", "w") as ouf:
#     json.dump(arr, fp=ouf)
