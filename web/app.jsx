console.log('APP.JSX LOADED - VERSION 12 (PERFECT TREE)');

const { useState, useEffect } = React;

// Simple SVG icons
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

// Process List component
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

// Perfect Process Tree component
const PerfectProcessTree = ({ processes, selectedProcess, onSelectProcess }) => {
  if (!selectedProcess) return null;
  
  const [treeNodes, setTreeNodes] = useState([]);
  
  // Function to find a process by PID
  const findProcessByPid = (pid) => {
    return processes.find(p => p.pid === pid);
  };
  
  // Function to find all processes with a specific PPID (children)
  const findChildProcesses = (pid) => {
    return processes.filter(p => p.ppid === pid);
  };
  
  // Build the process tree when selected process changes
  useEffect(() => {
    if (!selectedProcess) return;
    
    const tree = [];
    
    // Find the most distant ancestor (to prevent infinite loops, limit to 10 levels)
    const findRootAncestor = (process, maxDepth = 10) => {
      let current = process;
      let ancestors = [];
      let depth = 0;
      
      while (current.ppid > 0 && depth < maxDepth) {
        const parent = findProcessByPid(current.ppid);
        if (!parent) break;
        
        ancestors.unshift(parent);
        current = parent;
        depth++;
      }
      
      return ancestors;
    };
    
    // Get all ancestors
    const ancestors = findRootAncestor(selectedProcess);
    
    // Add all ancestors to the tree
    ancestors.forEach(ancestor => {
      tree.push({
        process: ancestor,
        type: 'ancestor'
      });
    });
    
    // Add the selected process
    tree.push({
      process: selectedProcess,
      type: 'selected'
    });
    
    // Find direct children
    const children = findChildProcesses(selectedProcess.pid);
    
    // Add children
    children.forEach(child => {
      tree.push({
        process: child,
        type: 'child'
      });
    });
    
    setTreeNodes(tree);
  }, [selectedProcess, processes]);
  
  // Helper to get file name from path
  const getFileName = (path, comm) => {
    if (path) {
      const parts = path.split('/');
      return parts[parts.length - 1];
    }
    return comm || '-';
  };
  
  if (treeNodes.length === 0) return null;
  
  // Render tree nodes
  return (
    <div className="border-b border-gray-200 bg-gray-50 p-3 overflow-auto max-h-80">
      <div className="space-y-1">
        {treeNodes.map((node, index) => {
          const { process, type } = node;
          const pid = process.pid;
          const name = getFileName(process.exePath, process.comm);
          
          // Determine className based on node type
          let className = "font-mono text-sm cursor-pointer hover:bg-gray-100 py-1 px-2 rounded";
          if (type === 'selected') {
            className += " bg-blue-50 font-bold";
          }
          
          // Determine indentation and connector based on type
          let indentStyle = {};
          let connector = null;
          
          if (type === 'ancestor') {
            // For first ancestor (top level)
            if (index === 0) {
              connector = <span className="inline-block text-gray-400">└─</span>;
              indentStyle = { marginLeft: '16px' };
            } else {
              // For nested ancestors
              connector = <span className="inline-block text-gray-400">└─</span>;
              indentStyle = { marginLeft: '32px' };
            }
          } else if (type === 'selected') {
            connector = null;
            indentStyle = { marginLeft: '32px' };
          } else if (type === 'child') {
            connector = <span className="inline-block text-gray-400">└─</span>;
            indentStyle = { marginLeft: '32px' };
          }
          
          return (
            <div 
              key={process.pid} 
              className={className}
              onClick={() => onSelectProcess(process)}
            >
              <div style={indentStyle} className="flex items-center">
                {connector && <span className="mr-2">{connector}</span>}
                <span className="text-blue-600 mr-1">{pid}</span>
                <span>{name}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Process Details component
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
    <div className="p-6 space-y-4">
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
        <div className="font-mono bg-gray-50 p-3 rounded">{process.comm || '-'}</div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Command Line</label>
        <div className="font-mono bg-gray-50 p-3 rounded overflow-x-auto">
          {process.cmdline || '-'}
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Executable Path</label>
        <div className="font-mono bg-gray-50 p-3 rounded overflow-x-auto">
          {process.exePath || '-'}
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Working Directory</label>
        <div className="font-mono bg-gray-50 p-3 rounded overflow-x-auto">
          {process.workingDir || '-'}
        </div>
      </div>

      <div>
        <label className="text-sm font-medium text-gray-600">Environment Variables</label>
        <div className="bg-gray-50 p-3 rounded max-h-48 overflow-y-auto">
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
  const [sidebarWidth, setSidebarWidth] = useState(null);
  const [isResizing, setIsResizing] = useState(false);
  
  // Calculate default sidebar width based on window size
  const getDefaultSidebarWidth = () => {
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
    
    if (willExpand) {
      // If we're expanding, use either the saved width or default
      const expandedWidth = sidebarWidth || getDefaultSidebarWidth();
      const sidebarElement = document.querySelector('.sidebar-container');
      if (sidebarElement) {
        console.log(`Setting sidebar width to ${expandedWidth}px`);
        sidebarElement.style.width = `${expandedWidth}px`;
      }
    }
    
    setIsCollapsed(!isCollapsed);
  };

  // Resize handler
  const handleResizeStart = (e) => {
    // Only allow resize when the sidebar is expanded
    if (isCollapsed) return;
    
    // Prevent default browser behavior
    e.preventDefault();
    
    // Set resize flag
    setIsResizing(true);
    console.log('Resize started');
    
    // Save initial position and width
    const startX = e.clientX;
    const startWidth = sidebarWidth || getDefaultSidebarWidth();
    
    // Create mouse move handler
    const handleMouseMove = (moveEvent) => {
      // Calculate how far mouse has moved
      const deltaX = startX - moveEvent.clientX;
      
      // Calculate new width (moving left makes it wider)
      let newWidth = startWidth + deltaX;
      
      // Apply min/max constraints
      const minWidth = 250;
      const maxWidth = Math.min(windowWidth * 0.8, 800);
      newWidth = Math.max(minWidth, Math.min(maxWidth, newWidth));
      
      // Apply new width to sidebar
      const sidebarElement = document.querySelector('.sidebar-container');
      if (sidebarElement) {
        sidebarElement.style.width = `${newWidth}px`;
      }
    };
    
    // Create mouse up handler
    const handleMouseUp = (upEvent) => {
      console.log('Resize ended');
      setIsResizing(false);
      
      // Capture final width
      const sidebarElement = document.querySelector('.sidebar-container');
      if (sidebarElement) {
        // Get computed width (browser might have adjusted it)
        const computedStyle = window.getComputedStyle(sidebarElement);
        const finalWidth = parseInt(computedStyle.width, 10);
        console.log(`Final width: ${finalWidth}px`);
        setSidebarWidth(finalWidth);
      }
      
      // Remove event listeners
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
    
    // Add global event listeners
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  // Process selection handler
  const handleProcessSelect = (process) => {
    setSelectedProcess(process);
    
    if (isCollapsed) {
      console.log('Auto-expanding sidebar for process selection');
      const expandedWidth = sidebarWidth || getDefaultSidebarWidth();
      const sidebarElement = document.querySelector('.sidebar-container');
      if (sidebarElement) {
        console.log(`Setting sidebar width to ${expandedWidth}px`);
        sidebarElement.style.width = `${expandedWidth}px`;
      }
      setIsCollapsed(false);
    }
  };
  
  // Track window size
  useEffect(() => {
    const handleResize = () => {
      const newWidth = window.innerWidth;
      setWindowWidth(newWidth);
      
      // If sidebar is expanded and we don't have a manually set width,
      // update the sidebar width based on new window dimensions
      if (!isCollapsed && !sidebarWidth) {
        const sidebarElement = document.querySelector('.sidebar-container');
        if (sidebarElement) {
          const newDefaultWidth = getDefaultSidebarWidth();
          sidebarElement.style.width = `${newDefaultWidth}px`;
        }
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isCollapsed, sidebarWidth]);

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
      
      {/* Sidebar with resizable width */}
      <div 
        className="sidebar-container bg-white border-l shadow-lg flex-shrink-0 flex flex-col h-screen z-50"
        style={{ 
          position: windowWidth < 768 ? 'fixed' : 'relative',
          right: windowWidth < 768 ? '0' : 'auto',
          top: windowWidth < 768 ? '0' : 'auto',
          bottom: windowWidth < 768 ? '0' : 'auto',
          width: isCollapsed ? '48px' : `${sidebarWidth || getDefaultSidebarWidth()}px`,
          transition: isResizing ? 'none' : 'width 0.3s ease'
        }}
      >
        {/* Resize handle - only show when expanded */}
        {!isCollapsed && (
          <div
            className="absolute left-0 top-0 bottom-0 z-50"
            onMouseDown={handleResizeStart}
            style={{ 
              position: 'absolute',
              left: '-6px',  
              width: '12px',
              cursor: 'col-resize',
              backgroundColor: isResizing ? 'rgba(59, 130, 246, 0.3)' : 'transparent'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)';
            }}
            onMouseOut={(e) => {
              if (!isResizing) {
                e.currentTarget.style.backgroundColor = 'transparent';
              }
            }}
          >
            {/* Visual indicator for the resize handle */}
            <div 
              className="absolute left-6 top-0 bottom-0 w-0.5" 
              style={{ backgroundColor: '#d1d5db' }}
            />
          </div>
        )}

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

        {/* Sidebar content with perfect process tree at top */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Perfect Process Tree - only show when expanded and process is selected */}
          {!isCollapsed && selectedProcess && (
            <PerfectProcessTree 
              processes={processes} 
              selectedProcess={selectedProcess} 
              onSelectProcess={handleProcessSelect}
            />
          )}
          
          {/* Process Details */}
          <div className="flex-1 overflow-y-auto">
            {selectedProcess ? (
              <ProcessDetails process={selectedProcess} isCollapsed={isCollapsed} />
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
    </div>
  );
};

ReactDOM.render(React.createElement(App), document.getElementById('root'));