

merge with clamav like this:

unit_tests/
  CMakeLists.txt              - adds call to our py
  upx_tests.py                - test logic
  input/other_scanfiles/upx/
    *.upx                     - samples
    upx.ldb                   - sigs (*.ldb is fine)

You can run standalone with : python3 upx_test.py --standalone

To test in env rebuild
cmake ..
make
ctest -V -R upx_tests