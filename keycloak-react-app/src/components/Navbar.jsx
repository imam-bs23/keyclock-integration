import { Link, useNavigate } from "react-router-dom";
import useAuth from "../hooks/useAuth";
import { logout } from "../services/authService";

const Navbar = () => {
  const { authenticated, loading, updateAuthState } = useAuth();
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    navigate("/login");
  };

  const handleRegister = (e) => {
    e.preventDefault();
    navigate("/register");
  };

  const handleLogout = async (e) => {
    e.preventDefault();
    await logout();
    await updateAuthState();
  };

  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm sticky-top">
      <div className="container">
        <Link className="navbar-brand d-flex align-items-center" to="/">
          <i className="bi bi-shield-lock me-2"></i>
          <span>Keycloak Auth App</span>
        </Link>
        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#navbarNav"
        >
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav ms-auto">
            <li className="nav-item">
              <Link className="nav-link" to="/">
                <i className="bi bi-house-door me-1"></i> Home
              </Link>
            </li>

            {loading ? (
              <li className="nav-item">
                <span className="nav-link">
                  <div className="spinner-border spinner-border-sm" role="status">
                    <span className="visually-hidden">Loading...</span>
                  </div>
                </span>
              </li>
            ) : authenticated ? (
              <>
                <li className="nav-item">
                  <Link 
                    className="nav-link d-flex align-items-center" 
                    to="/profile"
                  >
                    <i className="bi bi-person-circle me-1"></i> Profile
                  </Link>
                </li>
                <li className="nav-item">
                  <a 
                    className="nav-link d-flex align-items-center" 
                    href="#" 
                    onClick={handleLogout}
                  >
                    <i className="bi bi-box-arrow-right me-1"></i> Logout
                  </a>
                </li>
              </>
            ) : (
              <>
                <li className="nav-item">
                  <a 
                    className="nav-link d-flex align-items-center" 
                    href="#" 
                    onClick={handleLogin}
                  >
                    <i className="bi bi-box-arrow-in-right me-1"></i> Login
                  </a>
                </li>
                <li className="nav-item">
                  <a 
                    className="nav-link d-flex align-items-center" 
                    href="#" 
                    onClick={handleRegister}
                  >
                    <i className="bi bi-person-plus me-1"></i> Register
                  </a>
                </li>
              </>
            )}
          </ul>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
