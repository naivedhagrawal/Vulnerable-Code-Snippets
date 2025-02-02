@Library('k8s-shared-lib') _

pipeline {
    agent none
    environment {
        GITLEAKS_REPORT = 'gitleaks-report.csv'
        OWASP_DEP_REPORT = 'owasp-dep-report.html'
        ZAP_REPORT = 'zap-out.html'
        SEMGREP_REPORT = 'semgrep-report.json'
        TARGET_URL = 'https://juice-shop.herokuapp.com/'
        }

    stages {

        stage('Gitleak Check') {
            agent {
                kubernetes {
                    yaml pod('gitleak','zricethezav/gitleaks')
                    showRawYaml false
                }
            }
            steps {
                container('gitleak') {
                    sh """
                        gitleaks detect --source=. --report-path=${env.GITLEAKS_REPORT} --report-format csv --exit-code=0
                    """
                    archiveArtifacts artifacts: "${env.GITLEAKS_REPORT}"
                }
            }
        }
        stage('Owasp Dependency Check') {
            agent {
                kubernetes {
                    yaml pod('owasp','naivedh/owasp-dependency:latest')
                    showRawYaml false
                }
            }
            steps {
            container('owasp') {
                withCredentials([string(credentialsId: 'NVD_API_KEY', variable: 'NVD_API_KEY')]) {
                sh """
                    dependency-check --scan . --out ${env.OWASP_DEP_REPORT} --nvdApiKey ${env.NVD_API_KEY}
                """
                archiveArtifacts artifacts: "${env.OWASP_DEP_REPORT}"

                // script {
                //     def owaspReport = readJSON file: "${env.OWASP_DEP_REPORT}"
                //     def vulnerabilities = owaspReport.report.dependencies.collectMany { it.vulnerabilities }.findAll { it.severity == 'HIGH' || it.severity == 'CRITICAL' }

                //     if (vulnerabilities.size() > 0) {
                //     echo "High/Critical OWASP Vulnerabilities Found:"
                //     vulnerabilities.each { vuln ->
                //         echo "Dependency: ${vuln.name} - ${vuln.description} - CVE: ${vuln.cve}"
                //     }
                //     currentBuild.result = 'FAILURE'
                //     } else {
                //     echo "No High/Critical OWASP vulnerabilities found."
                //     }
                // }
                }
            }
            }
        }

        stage('Semgrep Scan') {
            agent {
                kubernetes {
                    yaml pod('semgrep','returntocorp/semgrep')
                    showRawYaml false
                }
            }
            steps {
            container('semgrep') {
                sh """
                semgrep --config=auto --json --output ${env.SEMGREP_REPORT} .
                """
                archiveArtifacts artifacts: "${env.SEMGREP_REPORT}"

                // script {
                // def semgrepReport = readJSON file: "${env.SEMGREP_REPORT}"
                // def criticalIssues = semgrepReport.results.findAll { it.severity == 'ERROR' || it.severity == 'WARNING' }

                // if (criticalIssues.size() > 0) {
                //     echo "Critical/Warning Semgrep Issues Found:"
                //     criticalIssues.each { issue ->
                //     echo "File: ${issue.path}:${issue.start.line} - ${issue.message} - Rule: ${issue.check_id}"
                //     }
                //     currentBuild.result = 'FAILURE'
                // } else {
                //     echo "No Critical/Warning Semgrep issues found."
                // }
                // }
            }
            }
        }

        stage('Owasp zap') {
            agent {
            kubernetes {
                yaml zap()
                showRawYaml false
            }
            }
            steps {
            container('zap') {
                // zap-api-scan.py zap-baseline.py zap-full-scan.py zap_common.py 
                sh """
                    zap-full-scan.py -t $TARGET_URL -r $ZAP_REPORT -l WARN -I
                    mv /zap/wrk/${ZAP_REPORT} .
                """
                archiveArtifacts artifacts: "${env.ZAP_REPORT}"
            }
            }
        }
        }
    }
