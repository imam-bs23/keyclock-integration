import { useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import useAuth from "../hooks/useAuth";

const Success = () => {
  const { updateAuthState } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Update auth state to reflect the new login
    updateAuthState();

    // Redirect to home page after a brief delay
    const timer = setTimeout(() => {
      navigate("/");
    }, 3000);

    return () => clearTimeout(timer);
  }, [navigate, updateAuthState]);

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow-lg border-0">
            <div className="card-body p-5 text-center">
              <div className="mb-4">
                <i className="bi bi-check-circle-fill text-success" style={{ fontSize: '4rem' }}></i>
              </div>
              <h2 className="card-title mb-3">Login Successful!</h2>
              <p className="card-text mb-4">
                You have been successfully authenticated with Keycloak.
              </p>
              <hr className="my-4" />
              <div className="d-flex align-items-center justify-content-center mb-4">
                <p className="mb-0 me-3">Redirecting to home page</p>
                <div className="spinner-border spinner-border-sm text-success" role="status">
                  <span className="visually-hidden">Loading...</span>
                </div>
              </div>
              <div className="d-grid gap-2">
                <Link to="/" className="btn btn-primary">
                  <i className="bi bi-house-door me-2"></i>
                  Go to Home Now
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Success;
