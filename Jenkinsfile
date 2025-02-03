@Library('k8s-shared-lib') _

pipeline {
    agent none
    environment {
        PROJECT_NAME = 'VCS'
        GITLEAKS_REPORT = 'gitleaks-report.sarif'
        OWASP_DEP_REPORT = 'owasp-dep-report.sarif'
        ZAP_REPORT = 'zap-out.html'
        SEMGREP_REPORT = 'semgrep-report.sarif'
        TARGET_URL = 'https://juice-shop.herokuapp.com/'
        DB_URL = 'jdbc:postgresql://postgres.devops-tools.svc.cluster.local:5432/postgres'
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
                        gitleaks detect --source=. --report-path=${env.GITLEAKS_REPORT} --report-format sarif --exit-code=0
                    """
                    recordIssues(
                        enabledForFailure: true,
                        tool: sarif(pattern: "${env.GITLEAKS_REPORT}") )
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
                    dependency-check --scan . --format SARIF --out ${env.OWASP_DEP_REPORT} --nvdApiKey ${env.NVD_API_KEY}
                """
                recordIssues(
                        enabledForFailure: true,
                        tool: sarif(pattern: "${env.OWASP_DEP_REPORT}") )
                archiveArtifacts artifacts: "${env.OWASP_DEP_REPORT}"
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
                semgrep --config=auto --sarif --output ${env.SEMGREP_REPORT} .
                """
                recordIssues(
                        enabledForFailure: true,
                        tool: sarif(pattern: "${env.SEMGREP_REPORT}") )
                archiveArtifacts artifacts: "${env.SEMGREP_REPORT}"
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
