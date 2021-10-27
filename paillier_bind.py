from typing import Mapping
import paillier_bind


print(paillier_bind.add(1, 2))

a = []
a.append(0)
b = []
b.append(2)

out = list()

out = paillier_bind.Paillier_GenKey(out)

print(out)
