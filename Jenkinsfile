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
            steps {
                script {
                    def jsonFile = '$WORKSPACE/env.SEMGREP_REPORT'
                    def tableName = env.PROJECT_NAME // Access environment variable
                    def jsonColumn = 'json_report_data' // Use underscores for column names (best practice)
                    def dbUser = 'postgres'
                    def dbPassword = credentials('postgres_password')
                    def dbName = 'semgrep'
                    def dbHost = 'postgres.devops-tools.svc.cluster.local:5432'

                    // Combined SQL for table creation and insertion
                    def combinedSQL = """
                        DO \$\$
                        BEGIN
                            IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = '${tableName}') THEN
                                CREATE TABLE ${tableName} (
                                    id SERIAL PRIMARY KEY,
                                    ${jsonColumn} JSONB
                                );
                            END IF;

                            -- Now, dynamically construct the INSERT statement based on JSON content
                            PERFORM populate_table('${jsonFile}', '${tableName}', '${jsonColumn}', '${dbUser}', '${dbPassword}', '${dbName}', '${dbHost}');

                        END \$\$;
                    """

                    // Create a PL/pgSQL function to handle the dynamic insertion
                    def createFunctionSQL = """
                        CREATE OR REPLACE FUNCTION populate_table(json_file_path TEXT, target_table TEXT, json_column_name TEXT, db_user TEXT, db_password TEXT, db_name TEXT, db_host TEXT)
                        RETURNS VOID AS \$\$
                        DECLARE
                            json_data jsonb;
                            item jsonb;
                        BEGIN
                            -- Read the JSON file (you may need to adjust this based on how your agent accesses the file)
                            EXECUTE format('SELECT pg_read_file(''%s'')', json_file_path) INTO json_data;

                            -- Connect to the database
                            PERFORM dblink_connect('host=' || db_host || ' dbname=' || db_name || ' user=' || db_user || ' password=' || db_password);

                            -- Handle JSON array or single object
                            IF json_data IS NOT NULL THEN
                            IF json_data IS NOT NULL AND json_data::text LIKE '[' || '%' || ']' THEN -- JSON array
                                FOR item IN SELECT json_array_elements(json_data) LOOP
                                    EXECUTE format('INSERT INTO %I (%I) VALUES (\$1::jsonb);', target_table, json_column_name) USING item;
                                END LOOP;
                            ELSE -- Single JSON object
                                EXECUTE format('INSERT INTO %I (%I) VALUES (\$1::jsonb);', target_table, json_column_name) USING json_data;
                            END IF;
                            END IF;
                            PERFORM dblink_disconnect();
                        END;
                        \$\$ LANGUAGE plpgsql;
                    """

                    sh """
                        psql -U ${dbUser} -d ${dbName} -h ${dbHost} -w -v ON_ERROR_STOP=1 -c "${createFunctionSQL}"
                    """

                    sh """
                        psql -U ${dbUser} -d ${dbName} -h ${dbHost} -w -v ON_ERROR_STOP=1 -c "${combinedSQL}"
                    """

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
