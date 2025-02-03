@Library('k8s-shared-lib') _

pipeline {
    agent none
    environment {
        PROJECT_NAME = 'VCS'
        GITLEAKS_REPORT = 'gitleaks-report.csv'
        OWASP_DEP_REPORT = 'owasp-dep-report.html'
        ZAP_REPORT = 'zap-out.html'
        SEMGREP_REPORT = 'semgrep-report.json'
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

        stage('Process and Insert JSON') {  // Combined stage
            agent{
                kubernetes {
                    yaml python_postgres()
                }
            }
            steps {
                script {
                    def jsonFile = "${WORKSPACE}/env.SEMGREP_REPORT"
                    def tableName = env.PROJECT_NAME
                    def jsonColumn = 'json_report_data'
                    def dbUser = 'postgres'
                    def dbPassword = credentials('postgres_password')
                    def dbName = 'semgrep'
                    def dbHost = 'postgres.devops-tools.svc.cluster.local'
                    def dbPort = '5432'

                    // Process JSON data using Python
                    container('python') {
                        sh """
                        python -c "
                        import json
                        with open('${jsonFile}', 'r') as f:
                            data = json.load(f)
                        # Perform any necessary processing on the data
                        with open('${jsonFile}', 'w') as f:
                            json.dump(data, f)
                        "
                        """
                    }

                    // SQL for table creation and insertion
                    def sqlCommands = """
                        DO \$\$
                        BEGIN
                            IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = '${tableName}') THEN
                                CREATE TABLE ${tableName} (
                                    id SERIAL PRIMARY KEY,
                                    """ + jsonColumn + """ JSONB
                                );
                            END IF;
                        END \$\$;
                    """

                    def insertSQL = """
                        INSERT INTO ${tableName} (${jsonColumn})
                        SELECT jsonb_strip_nulls(pg_read_file('${jsonFile}')::jsonb);
                    """

                    container('postgres') {
                        sh """
                            export PGPASSWORD=${dbPassword}
                            psql -U ${dbUser} -d ${dbName} -h ${dbHost} -p ${dbPort} -v ON_ERROR_STOP=1 -c "${sqlCommands}"
                            psql -U ${dbUser} -d ${dbName} -h ${dbHost} -p ${dbPort} -v ON_ERROR_STOP=1 -c "${insertSQL}"
                        """
                    }
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
