import { useState, useEffect } from 'react';
import { Container, Card, Form, Button, Alert, Accordion, Spinner } from 'react-bootstrap';
import axios from 'axios';

const Debug = () => {
  const [token, setToken] = useState('');
  const [tokenResult, setTokenResult] = useState(null);
  const [keycloakStatus, setKeycloakStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Check if we have a token in localStorage or sessionStorage
  useEffect(() => {
    const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token');
    if (storedToken) {
      try {
        const parsedToken = JSON.parse(storedToken);
        if (parsedToken.access_token) {
          setToken(parsedToken.access_token);
        }
      } catch (err) {
        // If it's not JSON, it might be the token itself
        setToken(storedToken);
      }
    }
  }, []);

  const checkKeycloakStatus = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.get('http://localhost:3001/api/debug/keycloak');
      setKeycloakStatus(response.data);
    } catch (err) {
      setError(`Error checking Keycloak status: ${err.response?.data?.message || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const validateToken = async () => {
    if (!token.trim()) {
      setError('Please enter a token');
      return;
    }

    setLoading(true);
    setError('');
    setTokenResult(null);

    try {
      const response = await axios.post('http://localhost:3001/api/debug/token', { token });
      setTokenResult(response.data);
    } catch (err) {
      setError(`Error validating token: ${err.response?.data?.message || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const formatJson = (json) => {
    return JSON.stringify(json, null, 2);
  };

  return (
    <Container className="mt-4">
      <h1>Keycloak Debug Tool</h1>
      <p className="text-muted">
        This tool helps diagnose issues with Keycloak authentication.
      </p>

      <Card className="mb-4">
        <Card.Header>Keycloak Server Status</Card.Header>
        <Card.Body>
          <Button 
            variant="primary" 
            onClick={checkKeycloakStatus} 
            disabled={loading}
          >
            {loading ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" />
                <span className="ms-2">Checking...</span>
              </>
            ) : (
              'Check Keycloak Status'
            )}
          </Button>

          {keycloakStatus && (
            <div className="mt-3">
              <Alert variant={keycloakStatus.status === 'success' ? 'success' : 'danger'}>
                Status: {keycloakStatus.status}
                {keycloakStatus.message && <div>Message: {keycloakStatus.message}</div>}
              </Alert>

              {keycloakStatus.status === 'success' && (
                <Accordion className="mt-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header>Keycloak Configuration</Accordion.Header>
                    <Accordion.Body>
                      <pre className="bg-light p-3 rounded">
                        {formatJson({
                          keycloak_url: keycloakStatus.keycloak_url,
                          realm: keycloakStatus.realm,
                          client_id: keycloakStatus.client_id,
                          issuer: keycloakStatus.issuer,
                          token_endpoint: keycloakStatus.token_endpoint
                        })}
                      </pre>
                    </Accordion.Body>
                  </Accordion.Item>
                  <Accordion.Item eventKey="1">
                    <Accordion.Header>Available Realms</Accordion.Header>
                    <Accordion.Body>
                      <pre className="bg-light p-3 rounded">
                        {formatJson(keycloakStatus.available_realms)}
                      </pre>
                    </Accordion.Body>
                  </Accordion.Item>
                  <Accordion.Item eventKey="2">
                    <Accordion.Header>Client Information</Accordion.Header>
                    <Accordion.Body>
                      <div className="mb-3">
                        <strong>Current Client:</strong>
                        <pre className="bg-light p-3 rounded">
                          {formatJson(keycloakStatus.current_client)}
                        </pre>
                      </div>
                      <div>
                        <strong>All Clients:</strong>
                        <pre className="bg-light p-3 rounded">
                          {formatJson(keycloakStatus.clients)}
                        </pre>
                      </div>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
              )}
            </div>
          )}
        </Card.Body>
      </Card>

      <Card>
        <Card.Header>Token Validation</Card.Header>
        <Card.Body>
          <Form.Group className="mb-3">
            <Form.Label>Access Token</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Paste your JWT token here"
            />
          </Form.Group>
          <Button 
            variant="primary" 
            onClick={validateToken}
            disabled={loading}
          >
            {loading ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" />
                <span className="ms-2">Validating...</span>
              </>
            ) : (
              'Validate Token'
            )}
          </Button>

          {error && (
            <Alert variant="danger" className="mt-3">
              {error}
            </Alert>
          )}

          {tokenResult && (
            <div className="mt-3">
              <Alert variant={tokenResult.status === 'success' ? 'success' : 'danger'}>
                Status: {tokenResult.status}
                {tokenResult.message && <div>Message: {tokenResult.message}</div>}
              </Alert>

              {tokenResult.status === 'success' && (
                <Accordion className="mt-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header>
                      Token Format
                      {!tokenResult.token_format.valid_format && (
                        <span className="ms-2 text-danger">(Invalid)</span>
                      )}
                    </Accordion.Header>
                    <Accordion.Body>
                      <pre className="bg-light p-3 rounded">
                        {formatJson(tokenResult.token_format)}
                      </pre>
                    </Accordion.Body>
                  </Accordion.Item>
                  <Accordion.Item eventKey="1">
                    <Accordion.Header>
                      Token Validation
                      {tokenResult.validation.valid ? (
                        <span className="ms-2 text-success">(Valid)</span>
                      ) : (
                        <span className="ms-2 text-danger">(Invalid)</span>
                      )}
                    </Accordion.Header>
                    <Accordion.Body>
                      <pre className="bg-light p-3 rounded">
                        {formatJson(tokenResult.validation)}
                      </pre>
                    </Accordion.Body>
                  </Accordion.Item>
                  <Accordion.Item eventKey="2">
                    <Accordion.Header>
                      User Info
                      {tokenResult.userinfo.success ? (
                        <span className="ms-2 text-success">(Success)</span>
                      ) : (
                        <span className="ms-2 text-danger">(Failed)</span>
                      )}
                    </Accordion.Header>
                    <Accordion.Body>
                      <pre className="bg-light p-3 rounded">
                        {formatJson(tokenResult.userinfo)}
                      </pre>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
              )}
            </div>
          )}
        </Card.Body>
      </Card>
    </Container>
  );
};

export default Debug;
