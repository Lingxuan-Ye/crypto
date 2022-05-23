python ../../crypto.py -p "hello world"
python ../../crypto.py -p "hello world" -f ../__raw__ -s ../__result__/__en__
python ../../crypto.py -p "hello world" -f test.bat -s ../__result__/__en_single__
python ../../crypto.py -p "hello world" -e -f ../__raw__ -s ../__result__/__en_option_e__
python ../../crypto.py -p "hello world" -V 0 -f ../__raw__ -s ../__result__/__en_ver_0__
python ../../crypto.py -p "hello world" -V 1 -f ../__raw__ -s ../__result__/__en_ver_1__
python ../../crypto.py -p "hello world" -V 2 -f ../__raw__ -s ../__result__/__en_ver_2__
python ../../crypto.py -p "goodbye world" -f ../__raw__ -s ../__result__/__en_diff_passwd__

python ../../crypto.py -p "hello world" -d
python ../../crypto.py -p "hello world" -d -f ../__result__/__en__ -s ../__result__/__de__
python ../../crypto.py -p "hello world" -d -f ../__result__/__en_single__ -s ../__result__/__de_single__
python ../../crypto.py -p "hello world" -d -f ../__result__/__en_option_e__ -s ../__result__/__de_option_e__
python ../../crypto.py -p "hello world" -d -f ../__result__/__en_ver_0__ -s ../__result__/__de_ver_0__
python ../../crypto.py -p "hello world" -d -f ../__result__/__en_ver_1__ -s ../__result__/__de_ver_1__
python ../../crypto.py -p "hello world" -d -f ../__result__/__en_ver_2__ -s ../__result__/__de_ver_2__
python ../../crypto.py -p "hello world" -d -f ../__result__/__en_diff_passwd__ -s ../__result__/__de_diff_passwd__


python compare.py __decrypted__/clear.bat clear.bat
python compare.py __decrypted__/compare.py compare.py
python compare.py __decrypted__/test.bat test.bat
python compare.py ../__result__/__de__ ../__raw__
python compare.py ../__result__/__de_single__ test.bat
python compare.py ../__result__/__de_ver_0__ ../__raw__
python compare.py ../__result__/__de_ver_1__ ../__raw__
python compare.py ../__result__/__de_ver_2__ ../__raw__
