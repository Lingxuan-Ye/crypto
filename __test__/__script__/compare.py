import sys
from hashlib import sha256
from pathlib import Path

_, x, y = sys.argv

X = Path(x)
Y = Path(y)

x_hashlist = []
y_hashlist = []

path_list = [Path(X)]
x_list = []
while path_list:
    path = path_list.pop()
    if path.is_file():
        x_list.append(path)
    elif path.is_dir():
        path_list.extend(path.iterdir())

path_list = [Path(Y)]
y_list = []
while path_list:
    path = path_list.pop()
    if path.is_file():
        y_list.append(path)
    elif path.is_dir():
        path_list.extend(path.iterdir())

for i in x_list:
    with open(i, "rb") as f:
        x_hashlist.append(sha256(f.read()).hexdigest())
for i in y_list:
    with open(i, "rb") as g:
        y_hashlist.append(sha256(g.read()).hexdigest())
x_hashlist.sort()
y_hashlist.sort()

if all(x_hash == y_hash for x_hash, y_hash in zip(x_hashlist, y_hashlist)):
    print(f"files in {x} and {y} are all the same.")
else:
    print(f"files in {x} and {y} are NOT the same.")
