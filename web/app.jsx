console.log('APP.JSX LOADED - VERSION 4 (RESPONSIVE)');

const { useState, useEffect } = React;

// Simple SVG icons for sidebar toggle
const ChevronLeftIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" 
       stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M15 18l-6-6 6-6" />
  </svg>
);

const ChevronRightIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" 
       stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 18l6-6-6-6" />
  </svg>
);

const ProcessList = ({ processes, onSelectProcess }) => {
  return (
    <div className="bg-white shadow-sm rounded-lg overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">PID</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">PPID</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Command</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Command Line</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Container</th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {processes.map((process) => (
            <tr
              key={process.id}
              onClick={() => onSelectProcess(process)}
              className="hover:bg-gray-50 cursor-pointer"
            >
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {new Date(process.timestamp).toLocaleString()}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{process.pid}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{process.ppid}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm font-mono">{process.comm || '-'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm font-mono overflow-hidden text-ellipsis" style={{maxWidth: '300px'}}>
                {process.cmdline || '-'}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{process.username}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {process.containerId || '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const ProcessDetails = ({ process, isCollapsed }) => {
  if (!process) return null;

  // If collapsed, return minimal view
  if (isCollapsed) {
    return (
      <div className="p-2 text-center">
        <div className="font-mono text-sm truncate">{process.pid}</div>
      </div>
    );
  }

  // Full view
  const formatEnvironment = () => {
    try {
      const env = JSON.parse(process.environment || '[]');
      return env.map(e => {
        const [key, value] = e.split('=');
        return (
          <div key={key} className="text-sm">
            <span className="font-medium text-blue-600">{key}</span>=
            <span className="text-gray-700">{value}</span>
          </div>
        );
      });
    } catch (e) {
      return <div className="text-red-500">Error parsing environment variables</div>;
    }
  };

  return (
    <div className="p-4 space-y-4">
      <h3 className="text-lg font-semibold border-b pb-2">Process Details</h3>
      
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-sm font-medium text-gray-600">PID</label>
          <div className="text-lg">{process.pid}</div>
        </div>
        <div>
          <label className="text-sm font-medium text-gray-600">PPID</label>
          <div className="text-lg">{process.ppid}</div>
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Command</label>
        <div className="font-mono bg-gray-50 p-2 rounded">{process.comm || '-'}</div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Command Line</label>
        <div className="font-mono bg-gray-50 p-2 rounded overflow-x-auto">
          {process.cmdline || '-'}
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Executable Path</label>
        <div className="font-mono bg-gray-50 p-2 rounded overflow-x-auto">
          {process.exePath || '-'}
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Working Directory</label>
        <div className="font-mono bg-gray-50 p-2 rounded overflow-x-auto">
          {process.workingDir || '-'}
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Environment Variables</label>
        <div className="bg-gray-50 p-2 rounded max-h-48 overflow-y-auto">
          {formatEnvironment()}
        </div>
      </div>
    </div>
  );
};

const App = () => {
  const [processes, setProcesses] = useState([]);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isCollapsed, setIsCollapsed] = useState(true);
  const [windowWidth, setWindowWidth] = useState(window.innerWidth);
  
  // Calculate sidebar width based on window size
  const getExpandedSidebarWidth = () => {
    // For very narrow screens
    if (windowWidth < 640) {
      return Math.min(windowWidth * 0.9, 350); // 90% of screen up to 350px
    }
    
    // For medium screens
    if (windowWidth < 1024) {
      return Math.min(windowWidth * 0.4, 400); // 40% of screen up to 400px
    }
    
    // For large screens
    return Math.min(windowWidth * 0.3, 500); // 30% of screen up to 500px
  };
  
  // Function to toggle sidebar state
  const toggleSidebar = () => {
    const willExpand = isCollapsed;
    console.log(willExpand ? 'EXPANDING sidebar' : 'COLLAPSING sidebar');
    
    const sidebarElement = document.querySelector('.sidebar-container');
    if (sidebarElement) {
      if (willExpand) {
        const expandedWidth = getExpandedSidebarWidth();
        console.log(`Setting sidebar width to ${expandedWidth}px`);
        sidebarElement.style.width = `${expandedWidth}px`;
      } else {
        sidebarElement.style.width = '48px';
      }
    }
    
    setIsCollapsed(!isCollapsed);
  };

  // Process selection handler
  const handleProcessSelect = (process) => {
    setSelectedProcess(process);
    
    if (isCollapsed) {
      console.log('Auto-expanding sidebar for process selection');
      const sidebarElement = document.querySelector('.sidebar-container');
      if (sidebarElement) {
        const expandedWidth = getExpandedSidebarWidth();
        console.log(`Setting sidebar width to ${expandedWidth}px`);
        sidebarElement.style.width = `${expandedWidth}px`;
      }
      setIsCollapsed(false);
    }
  };
  
  // Track window size
  useEffect(() => {
    const handleResize = () => {
      setWindowWidth(window.innerWidth);
      
      // Also update sidebar width if it's already expanded
      if (!isCollapsed) {
        const sidebarElement = document.querySelector('.sidebar-container');
        if (sidebarElement) {
          const expandedWidth = getExpandedSidebarWidth();
          sidebarElement.style.width = `${expandedWidth}px`;
        }
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isCollapsed]);

  // Fetch process data
  useEffect(() => {
    fetchProcesses();
    if (autoRefresh) {
      const interval = setInterval(fetchProcesses, 5000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);
    
  const fetchProcesses = async () => {
    try {
      const response = await fetch('/api/processes');
      const data = await response.json();
      setProcesses(data);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex overflow-hidden relative">  
      {/* Main content area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden"> 
        <nav className="bg-white shadow-sm flex-shrink-0"> 
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex items-center">
                <h1 className="text-xl font-bold text-gray-900">BPF Process Monitor</h1>
              </div>
              <div className="flex items-center">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={autoRefresh}
                    onChange={(e) => setAutoRefresh(e.target.checked)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-600">Auto-refresh</span>
                </label>
              </div>
            </div>
          </div>
        </nav>

        <main className="flex-1 overflow-auto p-4">
          {loading ? (
            <div className="text-center py-12">Loading...</div>
          ) : error ? (
            <div className="text-center py-12 text-red-600">{error}</div>
          ) : (
            <ProcessList 
              processes={processes} 
              onSelectProcess={handleProcessSelect} 
            />
          )}
        </main>
      </div>
          
      {/* Dark overlay for mobile */}
      {!isCollapsed && windowWidth < 768 && (
        <div 
          className="fixed inset-0 bg-black/30 z-40"
          onClick={toggleSidebar}
        />
      )}
      
      {/* Sidebar with responsive width */}
      <div 
        className="sidebar-container bg-white border-l shadow-lg flex-shrink-0 flex flex-col h-screen z-50"
        style={{ 
          position: windowWidth < 768 ? 'fixed' : 'relative',
          right: windowWidth < 768 ? '0' : 'auto',
          top: windowWidth < 768 ? '0' : 'auto',
          bottom: windowWidth < 768 ? '0' : 'auto',
          width: isCollapsed ? '48px' : `${getExpandedSidebarWidth()}px`,
          transition: 'width 0.3s ease'
        }}
      >
        {/* Collapse/Expand toggle button */}
        <div className="absolute left-0 top-16 -translate-x-full">
          <button
            onClick={toggleSidebar}
            className="flex items-center justify-center w-6 h-20 bg-white border-t border-b border-l 
                     rounded-l-lg hover:bg-gray-50 shadow-sm"
            title={isCollapsed ? "Show details" : "Hide details"}
          >
            {isCollapsed ? <ChevronLeftIcon /> : <ChevronRightIcon />}
          </button>
        </div>

        {/* Sidebar content */}
        <div className="flex-1 overflow-y-auto">
          {selectedProcess ? (
            <div>
              <ProcessDetails process={selectedProcess} isCollapsed={isCollapsed} />
            </div>
          ) : (
            <div className="flex items-center justify-center h-full p-8 text-center text-gray-500">
              {!isCollapsed && (
                <div>
                  <p className="text-lg mb-2">No Process Selected</p>
                  <p className="text-sm">Click on a process to view its details</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

ReactDOM.render(React.createElement(App), document.getElementById('root'));