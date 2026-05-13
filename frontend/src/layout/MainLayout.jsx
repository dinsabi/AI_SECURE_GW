import { Box } from "@mui/material";
import Sidebar from "./Sidebar.jsx";
import Header from "./Header.jsx";

export default function MainLayout({ children, activePage, setActivePage }) {
  return (
    <Box sx={{ display: "flex", minHeight: "100vh", background: "#0b1020" }}>
      <Sidebar activePage={activePage} setActivePage={setActivePage} />

      <Box sx={{ flexGrow: 1, display: "flex", flexDirection: "column" }}>
        <Header />

        <Box
          component="main"
          sx={{
            flexGrow: 1,
            p: 3,
            color: "#fff",
          }}
        >
          {children}
        </Box>
      </Box>
    </Box>
  );
}