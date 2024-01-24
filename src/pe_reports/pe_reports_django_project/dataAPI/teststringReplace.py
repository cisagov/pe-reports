
# path = "../../"
#
# dir_list = os.listdir(path)
#
# for file in dir_list:
#     if file.endswith("copyofenv"):




exampleTxt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzE3MzE4NzIsInN1YiI6ImNkdWhuNzUifQ.TXZIFqF7-MyMUH9Bt6FyquJpWpVhEOUFksXNJaL1T6U'
replacementTxt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzE3MzA5MDMsInN1YiI6ImNkdWhuNzUifQ.JH9n6Hfs3nUiNQFFvyd7yqH1bNCySa4lcp1QMq_-7ec'


with open("../.env", 'r') as f:
    f.seek(0)
    data = f.read()
data2 = data.replace(exampleTxt, replacementTxt)
print(data)
with open("../.env", 'w') as f:
    if exampleTxt in data:
        print('Changing file...\n')

        f.write(data2)

        print(data2)
    else:
        pass
