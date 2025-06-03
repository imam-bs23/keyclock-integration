import { Route, BrowserRouter as Router, Routes } from "react-router-dom";
import "./App.css";
import Navbar from "./components/Navbar";
import AuthProvider from "./context/AuthContext";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Success from "./pages/Success";
import Callback from "./pages/Callback";
import Debug from "./pages/Debug";
import Profile from "./pages/Profile";

// Import Bootstrap CSS and icons
import "bootstrap-icons/font/bootstrap-icons.css";
import "bootstrap/dist/css/bootstrap.min.css";

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="d-flex flex-column min-vh-100 vw-100">
          <Navbar />
          <main className="flex-grow-1">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/profile" element={<Profile />} />
              <Route path="/success" element={<Success />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/callback" element={<Callback />} />
              <Route path="/debug" element={<Debug />} />
            </Routes>
          </main>
          <footer className="bg-light py-3 mt-auto">
            <div className="container text-center">
              <span className="text-muted">© 2025 Keycloak Auth App</span>
            </div>
          </footer>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
