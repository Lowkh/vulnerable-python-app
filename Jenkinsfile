pipeline {
    agent any

    environment {
        SNYK_TOKEN   = credentials('snyk-token')
        DOCKER_IMAGE = 'vulnerable-python-app'
        DOCKER_TAG   = "${BUILD_NUMBER}"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup Snyk') {
            steps {
                sh '''
                    # Check if Snyk is installed
                    if command -v snyk &> /dev/null; then
                        echo "Snyk CLI is already installed"
                        snyk --version
                    else
                        echo "Installing Snyk CLI..."
                        
                        # Download Snyk binary
                        curl -Lo ./snyk https://static.snyk.io/cli/latest/snyk-linux
                        chmod +x ./snyk
                        
                        # Move to a location in PATH that doesn't require sudo
                        mkdir -p ${WORKSPACE}/bin
                        mv ./snyk ${WORKSPACE}/bin/
                        export PATH="${WORKSPACE}/bin:$PATH"
                        
                        echo "Snyk installed to ${WORKSPACE}/bin/"
                        ${WORKSPACE}/bin/snyk --version
                    fi

                    # Authenticate with Snyk
                    if command -v snyk &> /dev/null; then
                        snyk auth ${SNYK_TOKEN}
                    else
                        ${WORKSPACE}/bin/snyk auth ${SNYK_TOKEN}
                    fi
                    
                    echo "Snyk authentication successful"
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    echo "Building Docker image..."
                    
                    # Check if Docker is available
                    if ! command -v docker &> /dev/null; then
                        echo "ERROR: Docker is not installed or not available in PATH"
                        exit 1
                    fi
                    
                    docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .
                    docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest
                    
                    echo "Docker image built successfully"
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                sh '''
                    echo "Running unit tests..."
                    
                    # Check if test file exists
                    if [ -f test_app.py ]; then
                        docker run --rm ${DOCKER_IMAGE}:${DOCKER_TAG} python test_app.py
                    elif [ -d tests ]; then
                        docker run --rm ${DOCKER_IMAGE}:${DOCKER_TAG} python -m pytest tests/ -v
                    else
                        echo "No tests found, skipping..."
                    fi
                '''
            }
        }

        stage('Snyk Security Scan - Dependencies') {
            steps {
                script {
                    sh '''
                        echo "Scanning Python dependencies..."
                        mkdir -p reports
                        cd ${WORKSPACE}
                        
                        # Set PATH to include workspace bin
                        export PATH="${WORKSPACE}/bin:$PATH"

                        if [ -f requirements.txt ]; then
                            echo "requirements.txt found"
                            cat requirements.txt
                        else
                            echo "WARNING: requirements.txt not found"
                            exit 0
                        fi

                        # Use full path to snyk if needed
                        SNYK_CMD="snyk"
                        if [ -f ${WORKSPACE}/bin/snyk ]; then
                            SNYK_CMD="${WORKSPACE}/bin/snyk"
                        fi

                        ${SNYK_CMD} test --file=./requirements.txt --package-manager=pip --json > reports/snyk-deps-report.json || true

                        echo "=== Dependency Scan Results ==="
                        if [ -s reports/snyk-deps-report.json ]; then
                            ${SNYK_CMD} test --file=./requirements.txt --package-manager=pip || true
                        else
                            echo "No dependency scan results available"
                        fi
                    '''

                    def hasVulnerabilities = sh(
                        script: 'test -s reports/snyk-deps-report.json && grep -q "\\"severity\\":\\"critical\\"" reports/snyk-deps-report.json',
                        returnStatus: true
                    )
                    if (hasVulnerabilities == 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "WARNING: Critical vulnerabilities found in dependencies"
                    }
                }
            }
        }

        stage('Snyk Security Scan - Docker Image') {
            steps {
                script {
                    sh '''
                        echo "Scanning Docker image..."
                        
                        # Set PATH to include workspace bin
                        export PATH="${WORKSPACE}/bin:$PATH"
                        
                        SNYK_CMD="snyk"
                        if [ -f ${WORKSPACE}/bin/snyk ]; then
                            SNYK_CMD="${WORKSPACE}/bin/snyk"
                        fi

                        ${SNYK_CMD} container test ${DOCKER_IMAGE}:${DOCKER_TAG} --json > reports/snyk-container-report.json || true

                        echo "=== Container Scan Results ==="
                        ${SNYK_CMD} container test ${DOCKER_IMAGE}:${DOCKER_TAG} || true
                    '''

                    def hasVulnerabilities = sh(
                        script: 'test -s reports/snyk-container-report.json && grep -q "vulnerabilities" reports/snyk-container-report.json',
                        returnStatus: true
                    )
                    if (hasVulnerabilities == 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "WARNING: Vulnerabilities found in container image"
                    }
                }
            }
        }

        stage('Snyk Code Analysis') {
            steps {
                script {
                    sh '''
                        echo "Running static code analysis..."
                        
                        # Set PATH to include workspace bin
                        export PATH="${WORKSPACE}/bin:$PATH"
                        
                        SNYK_CMD="snyk"
                        if [ -f ${WORKSPACE}/bin/snyk ]; then
                            SNYK_CMD="${WORKSPACE}/bin/snyk"
                        fi

                        ${SNYK_CMD} code test --json > reports/snyk-code-report.json || true

                        echo "=== Code Analysis Results ==="
                        ${SNYK_CMD} code test || true
                    '''

                    def hasIssues = sh(
                        script: 'test -s reports/snyk-code-report.json',
                        returnStatus: true
                    )
                    if (hasIssues == 0) {
                        echo "Code quality issues detected"
                    }
                }
            }
        }

        stage('Generate Security Report') {
            steps {
                sh '''
                    echo "Generating consolidated security report..."
                    mkdir -p reports

                    cat > reports/security-summary.txt << EOF
=== Security Scan Summary ===
Build Number: ${BUILD_NUMBER}
Date: $(date)
Image: ${DOCKER_IMAGE}:${DOCKER_TAG}
EOF

                    # Dependency vulnerabilities
                    if [ -f reports/snyk-deps-report.json ]; then
                        echo "## Dependency Vulnerabilities:" >> reports/security-summary.txt
                        echo "Total: $(grep -o '"severity"' reports/snyk-deps-report.json | wc -l)" >> reports/security-summary.txt
                        echo "Critical: $(grep -o '"severity":"critical"' reports/snyk-deps-report.json | wc -l)" >> reports/security-summary.txt
                        echo "High: $(grep -o '"severity":"high"' reports/snyk-deps-report.json | wc -l)" >> reports/security-summary.txt
                        echo "Medium: $(grep -o '"severity":"medium"' reports/snyk-deps-report.json | wc -l)" >> reports/security-summary.txt
                        echo "Low: $(grep -o '"severity":"low"' reports/snyk-deps-report.json | wc -l)" >> reports/security-summary.txt
                        echo "" >> reports/security-summary.txt
                    fi

                    # Container vulnerabilities
                    if [ -f reports/snyk-container-report.json ]; then
                        echo "## Container Vulnerabilities:" >> reports/security-summary.txt
                        echo "Total: $(grep -o '"severity"' reports/snyk-container-report.json | wc -l)" >> reports/security-summary.txt
                        echo "" >> reports/security-summary.txt
                    fi

                    # Code issues
                    if [ -f reports/snyk-code-report.json ]; then
                        echo "## Code Issues:" >> reports/security-summary.txt
                        echo "Total: $(grep -o '"issue"' reports/snyk-code-report.json | wc -l)" >> reports/security-summary.txt
                        echo "" >> reports/security-summary.txt
                    fi

                    cat reports/security-summary.txt
                '''
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
                script {
                    if (fileExists('reports/security-summary.txt')) {
                        echo "Security reports have been archived"
                    }
                }
            }
        }

        stage('Snyk Monitor - Push to Dashboard') {
            steps {
                sh '''
                    echo "Pushing results to Snyk dashboard for continuous monitoring..."
                    
                    # Set PATH to include workspace bin
                    export PATH="${WORKSPACE}/bin:$PATH"
                    
                    SNYK_CMD="snyk"
                    if [ -f ${WORKSPACE}/bin/snyk ]; then
                        SNYK_CMD="${WORKSPACE}/bin/snyk"
                    fi

                    echo "Monitoring dependencies..."
                    cd ${WORKSPACE}
                    ${SNYK_CMD} monitor --file=./requirements.txt \
                        --project-name="vulnerable-python-app-deps-build-${BUILD_NUMBER}" \
                        --remote-repo-url="https://github.com/eugeneswee/vulnerable-python-app" || true

                    echo "Monitoring container image..."
                    ${SNYK_CMD} container monitor ${DOCKER_IMAGE}:${DOCKER_TAG} \
                        --project-name="vulnerable-python-app-container-build-${BUILD_NUMBER}" || true

                    echo "Monitoring code..."
                    ${SNYK_CMD} code test --report \
                        --project-name="vulnerable-python-app-code-build-${BUILD_NUMBER}" || true

                    echo ""
                    echo "============================================"
                    echo "Projects should now appear in Snyk dashboard:"
                    echo "https://app.snyk.io"
                    echo "============================================"
                '''
            }
        }
    }

    post {
        always {
            sh '''
                echo "Cleaning up Docker images..."
                
                # Check if Docker is available before cleanup
                if command -v docker &> /dev/null; then
                    docker rmi ${DOCKER_IMAGE}:${DOCKER_TAG} || true
                    docker rmi ${DOCKER_IMAGE}:latest || true
                else
                    echo "Docker not available for cleanup"
                fi
            '''
        }

        success {
            echo 'Pipeline completed successfully!'
        }

        unstable {
            echo 'Pipeline completed with warnings. Security vulnerabilities detected!'
            echo 'Review the security reports in the archived artifacts.'
        }

        failure {
            echo 'Pipeline failed. Check the logs for details.'
        }
    }
}
