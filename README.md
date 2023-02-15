# Akto.io API Security
Akto is a plug-n-play API security platform that takes only 60 secs to get started. Akto is used by security teams to maintain a continuous inventory of APIs, test APIs for vulnerabilities and find runtime issues. Akto offers tests for all OWASP top 10 and HackerOne Top 10 categories including BOLA, authentication, SSRF, XSS, security configurations, etc. Akto's powerful testing engine runs variety of business logic tests by reading traffic data to understand API traffic pattern leading to reduced false positives. Akto can integrate with multiple traffic sources - burpsuite, AWS, postman, GCP, gateways, etc.

# What is Nuclei Wrapper?
A Golang wrapper around Nuclei. This allows Akto testing module to call custom Nuclei functions.

## Develop and contribute

#### Prerequisites
go1.19.4

#### Clone repo
1. `git clone https://github.com/akto-api-security/nuclei-wrapper.git`
2. cd nuclei-wrapper

#### Install dependencies and build executable
1. Install [go1.19.4](https://go.dev/doc/install)
2. Verify installation with `go version`
3. Run `gcc --version`. If this fails go to step 4 else skip to step 5.
4. a. `sudo yum groupinstall 'Development Tools'`(CentOS or Amazon Linux)
   b. `sudo apt-get install build-essential` (Debian)
5. `go install`
6. `go build -o nuclei_akto`

#### Run tests and view results
1. `mkdir files` (the directory where summary of the test will be stored)
2. `./nuclei_akto -u {{base_url}} -t {{nuclei-template-location}} -output-files-dir files -store-resp-dir calls -template-dir {{current_directory_path}} -v Method=GET -h {{header_key}}:"{{header_value}}"`
3.  All request and responses are stored in `calls/http/` and summary of the test is stored in `files/main.txt`

## Contributing

We welcome contributions to this project. Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for more information on how to get involved.

## License

This project is licensed under the [MIT License](LICENSE).
