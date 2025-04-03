const { useState, useEffect, useRef, useCallback } = React;

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
  
    console.log("Selected process:", selectedProcess);
  
    // Fetch the full process tree for the selected process
    fetch(`/api/processes?pid=${selectedProcess.pid}`)
      .then(response => response.json())
      .then(data => {
        console.log("Process tree data:", data);
        const tree = [];
      
        // Create a map of processes by PID for easy lookup
        const processMap = {};
        data.forEach(process => {
          processMap[process.pid] = process;
        });
      
        // Find the selected process in our fetched data
        const selected = processMap[selectedProcess.pid] || selectedProcess;
      
        // Traverse up to build ancestors
        const ancestors = [];
        let current = selected;
        while (current && current.ppid > 0) {
          const parent = processMap[current.ppid];
          if (!parent) break;
          ancestors.unshift(parent);
          current = parent;
        }
      
        // Add ancestors to tree
        ancestors.forEach(ancestor => {
          tree.push({
            process: ancestor,
            type: 'ancestor'
          });
        });
      
        // Add selected process
        tree.push({
          process: selected,
          type: 'selected'
        });
      
        // Find direct children (if any in our data)
        const children = data.filter(p => p.ppid === selected.pid);
      
        // Add children
        children.forEach(child => {
          tree.push({
            process: child,
            type: 'child'
          });
        });
      
        setTreeNodes(tree);
      })
      .catch(error => console.error('Error fetching process tree:', error));
  }, [selectedProcess]);
  
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

// Add this component to your app.jsx
const NetworkConnections = () => {
    const [connections, setConnections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [autoRefresh, setAutoRefresh] = useState(false);

    const fetchConnections = useCallback(async () => {
        try {
            const response = await fetch('/api/network');
            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }
            const data = await response.json();
            setConnections(data);
            setLoading(false);
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    }, []);

    // Fetch initially and set up auto-refresh if enabled
    useEffect(() => {
        fetchConnections();
        if (autoRefresh) {
            const interval = setInterval(fetchConnections, 5000);
            return () => clearInterval(interval);
        }
    }, [autoRefresh, fetchConnections]);

    if (loading) return <div className="text-center py-12">Loading network connections...</div>;
    if (error) return <div className="text-center py-12 text-red-600">Error: {error}</div>;

    return (
        <div className="bg-white shadow rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-200 flex justify-between items-center">
                <h2 className="text-lg font-medium text-gray-900">Network Connections</h2>
                <div className="flex items-center space-x-4">
                    <label className="flex items-center space-x-2">
                        <input
                            type="checkbox"
                            checked={autoRefresh}
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        />
                        <span className="text-sm text-gray-600">Auto-refresh</span>
                    </label>
                    <button
                        onClick={fetchConnections}
                        className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm"
                    >
                        Refresh
                    </button>
                </div>
            </div>

            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Process</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Operation</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Container</th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {connections.map((conn) => (
                            <tr key={conn.id} className="hover:bg-gray-50">
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {new Date(conn.timestamp).toLocaleString()}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="flex items-center">
                                        <div className="text-sm font-medium text-gray-900">
                                            {conn.processName}
                                        </div>
                                        <div className="ml-2 text-sm text-gray-500">
                                            ({conn.pid})
                                        </div>
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                        conn.operation === 'connect' ? 'bg-blue-100 text-blue-800' :
                                        conn.operation === 'accept' ? 'bg-green-100 text-green-800' :
                                        'bg-gray-100 text-gray-800'
                                    }`}>
                                        {conn.operation}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                                    {conn.srcAddr}:{conn.srcPort}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                                    {conn.dstAddr}:{conn.dstPort}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {conn.protocol}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {conn.containerId || '-'}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

// LeftNavigation component with explicit SVG icons
const LeftNavigation = ({ activeSection, onChangeSection, collapsed, onToggleCollapse }) => {
  // Define sections with icons and labels
  const sections = [
    { id: 'processes', label: 'Processes', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" 
           stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    )},
    { id: 'network', label: 'Network', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" 
           stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    )},
    { id: 'files', label: 'Files', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" 
           stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
        <polyline points="14 2 14 8 20 8" />
      </svg>
    )},
    { id: 'divider', type: 'divider' },
    { id: 'rules', label: 'Rules', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" 
           stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    )},
    { id: 'matches', label: 'Matches', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" 
           stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 0 1-3.46 0" />
      </svg>
    )}
  ];
  
  return (
    <div className={`h-screen bg-gray-800 text-white flex-shrink-0 transition-all duration-300 ${
      collapsed ? 'w-16' : 'w-56'
    }`}>
      {/* Header with title and hamburger menu */}
      <div className="p-4 flex items-center justify-between">
        {!collapsed ? (
          <h1 className="text-xl font-bold">BPF Monitor</h1>
        ) : (
          <div className="w-full text-center">
            {/* Monitor icon */}
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" 
                 stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mx-auto">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
          </div>
        )}
        
        <button 
          onClick={onToggleCollapse}
          className="text-gray-300 hover:text-white p-1 rounded focus:outline-none"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {/* Hamburger menu icon - always visible */}
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" 
               stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
      </div>
      
      {/* Navigation items */}
      <nav className="mt-6">
        <ul>
          {sections.map(section => 
            section.type === 'divider' ? (
              <li key={section.id} className="border-t border-gray-700 my-4"></li>
            ) : (
              <li key={section.id} className={`mb-2 ${collapsed ? 'px-0' : 'px-2'}`}>
                <button
                  onClick={() => onChangeSection(section.id)}
                  className={`w-full flex items-center py-2 ${collapsed ? 'justify-center px-0' : 'px-3'} rounded transition-colors ${
                    activeSection === section.id 
                      ? 'bg-blue-600 text-white' 
                      : 'text-gray-300 hover:bg-gray-700'
                  }`}
                  title={collapsed ? section.label : ''}
                >
                  <span className={collapsed ? 'mx-auto' : 'mr-3'}>
                    {section.icon}
                  </span>
                  {!collapsed && <span>{section.label}</span>}
                </button>
              </li>
            )
          )}
        </ul>
      </nav>
    </div>
  );
};

// SigmaRules component for rule management
const SigmaRules = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedRule, setSelectedRule] = useState(null);
  const [isCollapsed, setIsCollapsed] = useState(true);
  const [windowWidth, setWindowWidth] = useState(window.innerWidth);
  const [sidebarWidth, setSidebarWidth] = useState(null);
  const [isResizing, setIsResizing] = useState(false);
  
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadType, setUploadType] = useState('file'); // 'file' or 'paste'
  const [yamlContent, setYamlContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [uploadError, setUploadError] = useState(null);
  const fileInputRef = useRef(null);
  
  
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
  
  // Fetch all rules (both enabled and disabled)
  useEffect(() => {
    setLoading(true);
    fetch('/api/sigma/rules')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        // Make sure data is an array
        const rulesArray = Array.isArray(data) ? data : [];
        setRules(rulesArray);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error fetching rules:', error);
        setError(error.message);
        setLoading(false);
      });
  }, []);

  // Toggle rule enabled/disabled status
  const toggleRuleStatus = (ruleId) => {
    // Find the rule
    const rule = rules.find(r => r.id === ruleId);
    if (!rule) return;
    
    // Determine new status (opposite of current)
    const newStatus = !rule.enabled;
    
    // Call API to toggle status
    fetch(`/api/sigma/rules/toggle/${ruleId}`, {
      method: 'POST',
    })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        // Update the rules list
        setRules(rules.map(r => 
          r.id === ruleId ? {...r, enabled: newStatus} : r
        ));
        
        // If this was the selected rule, update it
        if (selectedRule && selectedRule.id === ruleId) {
          setSelectedRule({...selectedRule, enabled: newStatus});
        }
      })
      .catch(error => {
        console.error('Error toggling rule status:', error);
        alert(`Failed to update rule status: ${error.message}`);
      });
  };
  
  // Function to toggle sidebar state
  const toggleSidebar = () => {
    const willExpand = isCollapsed;
    console.log(willExpand ? 'EXPANDING sidebar' : 'COLLAPSING sidebar');
    
    if (willExpand) {
      // If we're expanding, use either the saved width or default
      const expandedWidth = sidebarWidth || getDefaultSidebarWidth();
      const sidebarElement = document.querySelector('.rule-sidebar-container');
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
      const sidebarElement = document.querySelector('.rule-sidebar-container');
      if (sidebarElement) {
        sidebarElement.style.width = `${newWidth}px`;
      }
    };
    
    // Create mouse up handler
    const handleMouseUp = (upEvent) => {
      console.log('Resize ended');
      setIsResizing(false);
      
      // Capture final width
      const sidebarElement = document.querySelector('.rule-sidebar-container');
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
  
  // Rule selection handler
  const handleRuleSelect = (rule) => {
    setSelectedRule(rule);
    
    if (isCollapsed) {
      console.log('Auto-expanding sidebar for rule selection');
      const expandedWidth = sidebarWidth || getDefaultSidebarWidth();
      const sidebarElement = document.querySelector('.rule-sidebar-container');
      if (sidebarElement) {
        console.log(`Setting sidebar width to ${expandedWidth}px`);
        sidebarElement.style.width = `${expandedWidth}px`;
      }
      setIsCollapsed(false);
    }
  };
  
  const handleRuleUpload = () => {
    // Clear previous errors
    setUploadError(null);
  
    let content = '';
    let name = '';
  
    if (uploadType === 'file') {
      // No file selected
      if (!fileInputRef.current || !fileInputRef.current.files || fileInputRef.current.files.length === 0) {
        setUploadError('Please select a file to upload');
        return;
      }
    
      // Use the selected file name
      name = fileInputRef.current.files[0].name;
    
      // We'll read the file in a moment
    } else {
      // Using pasted content
      if (!yamlContent.trim()) {
        setUploadError('Please enter YAML content');
        return;
      }
    
      content = yamlContent;
    
      // If no filename provided, generate one
      if (!fileName.trim()) {
        setUploadError('Please provide a filename for the rule');
        return;
      }
    
      name = fileName;
      // Add .yml extension if not present
      if (!name.endsWith('.yml') && !name.endsWith('.yaml')) {
        name += '.yml';
      }
    }
  
    // For file upload, read the file content
    if (uploadType === 'file') {
      const reader = new FileReader();
      reader.onload = (e) => {
        content = e.target.result;
        finishUpload(content, name);
      };
      reader.onerror = () => {
        setUploadError('Error reading file');
      };
      reader.readAsText(fileInputRef.current.files[0]);
    } else {
      // For pasted content, use it directly
      finishUpload(content, name);
    }
  };

  // Function to complete the upload process
  const finishUpload = (content, name) => {
    // Send to the server
    fetch('/api/sigma/rules/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        content: content,
        filename: name,
        enabled: true, // Default to enabled
      }),
    })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        // Success, close modal and refresh rules
        setShowUploadModal(false);
      
        // Clear form
        setYamlContent('');
        setFileName('');
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      
        // Refresh the rules list
        fetch('/api/sigma/rules')
          .then(response => response.json())
          .then(data => {
            const rulesArray = Array.isArray(data) ? data : [];
            setRules(rulesArray);
          });
      })
      .catch(error => {
        console.error('Error uploading rule:', error);
        setUploadError(`Failed to upload rule: ${error.message}`);
      });
  };
  
  // Track window size
  useEffect(() => {
    const handleResize = () => {
      const newWidth = window.innerWidth;
      setWindowWidth(newWidth);
      
      // If sidebar is expanded and we don't have a manually set width,
      // update the sidebar width based on new window dimensions
      if (!isCollapsed && !sidebarWidth) {
        const sidebarElement = document.querySelector('.rule-sidebar-container');
        if (sidebarElement) {
          const newDefaultWidth = getDefaultSidebarWidth();
          sidebarElement.style.width = `${newDefaultWidth}px`;
        }
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isCollapsed, sidebarWidth]);
  
  if (loading) return <div className="flex justify-center items-center h-full">Loading rules...</div>;
  if (error) return <div className="flex justify-center items-center h-full text-red-600">Error: {error}</div>;
  
  // Make sure rules is always an array, even if the API returns null
  const safeRules = rules || [];
  const enabledCount = safeRules.filter(r => r.enabled).length;
  
  return (
    <div className="flex h-full relative">
      {/* Main content area */}
      <div className="flex-1 overflow-auto">
        <div className="bg-white shadow rounded-lg overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b flex justify-between items-center">
            <h2 className="text-lg font-medium text-gray-700">Sigma Rules</h2>
            <div className="text-sm text-gray-500">
              {enabledCount} enabled / {safeRules.length} total
            </div>
            <button
              className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm"
              onClick={() => setShowUploadModal(true)}
            >
              Upload Rule
            </button>
          </div>
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Title</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {safeRules.length === 0 ? (
                <tr>
                  <td colSpan="4" className="px-6 py-4 text-center text-gray-500">
                    No rules found. Add rules to the rules directory to get started.
                  </td>
                </tr>
              ) : (
                safeRules.map(rule => (
                  <tr 
                    key={rule.id} 
                    className={`hover:bg-gray-50 cursor-pointer ${
                      selectedRule && selectedRule.id === rule.id ? 'bg-blue-50' : ''
                    }`}
                    onClick={() => handleRuleSelect(rule)}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        rule.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                      }`}>
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{rule.title}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono">{rule.id}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        rule.level === 'high' ? 'bg-red-100 text-red-800' :
                        rule.level === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {rule.level || 'low'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      
      {showUploadModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">Upload Sigma Rule</h3>

            {/* Upload Type Tabs */}
            <div className="flex border-b mb-4">
              <button
                className={`py-2 px-4 ${
                  uploadType === 'file' ? 'border-b-2 border-blue-500 font-medium' : 'text-gray-500'
                }`}
                onClick={() => setUploadType('file')}
              >
                Upload File
              </button>
              <button
                className={`py-2 px-4 ${
                  uploadType === 'paste' ? 'border-b-2 border-blue-500 font-medium' : 'text-gray-500'
                }`}
                onClick={() => setUploadType('paste')}
              >
                Paste YAML
              </button>
            </div>

            {/* File Upload Form */}
            {uploadType === 'file' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Select Sigma Rule File (.yml or .yaml)
                </label>
                <input
                  type="file"
                  accept=".yml,.yaml"
                  ref={fileInputRef}
                  className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
                />
              </div>
            )}

            {/* Paste YAML Form */}
            {uploadType === 'paste' && (
              <div>
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Filename (with .yml extension)
                  </label>
                  <input
                    type="text"
                    value={fileName}
                    onChange={(e) => setFileName(e.target.value)}
                    placeholder="myrule.yml"
                    className="w-full px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Paste YAML Content
                  </label>
                  <textarea
                    value={yamlContent}
                    onChange={(e) => setYamlContent(e.target.value)}
                    placeholder="title: My Rule\ndescription: Rule description\n..."
                    rows={10}
                    className="w-full px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono text-sm"
                  />
                </div>
              </div>
            )}

            {/* Error Message */}
            {uploadError && (
              <div className="mt-3 text-red-600 text-sm">
                {uploadError}
              </div>
            )}

            {/* Actions */}
            <div className="mt-6 flex justify-end space-x-3">
              <button
                className="px-4 py-2 border border-gray-300 rounded text-gray-700 hover:bg-gray-50"
                onClick={() => setShowUploadModal(false)}
              >
                Cancel
              </button>
              <button
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                onClick={handleRuleUpload}
              >
                Upload
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dark overlay for mobile */}
      {!isCollapsed && windowWidth < 768 && (
        <div 
          className="fixed inset-0 bg-black/30 z-40"
          onClick={toggleSidebar}
        />
      )}
      
      {/* Sidebar with resizable width */}
      <div 
        className="rule-sidebar-container bg-white border-l shadow-lg flex-shrink-0 flex flex-col h-full z-50"
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
            {isCollapsed ? (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" 
                   stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 18l-6-6 6-6" />
              </svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" 
                   stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 18l6-6-6-6" />
              </svg>
            )}
          </button>
        </div>
        
        {/* Rule Details */}
        <div className="flex-1 overflow-y-auto">
          {selectedRule ? (
            <div className={isCollapsed ? "p-2 text-center" : "p-6 space-y-4"}>
              {isCollapsed ? (
                <div className="font-mono text-sm truncate">{selectedRule.id}</div>
              ) : (
                <div>
                  <div className="flex justify-between items-center">
                    <h2 className="text-xl font-bold">{selectedRule.title}</h2>
                    <label className="inline-flex items-center cursor-pointer">
                      <input 
                        type="checkbox" 
                        className="sr-only"
                        checked={selectedRule.enabled}
                        onChange={() => toggleRuleStatus(selectedRule.id)}
                      />
                      <div className={`relative w-11 h-6 rounded-full transition ${
                        selectedRule.enabled ? 'bg-blue-600' : 'bg-gray-200'
                      }`}>
                        <div className={`absolute w-5 h-5 bg-white rounded-full shadow transform transition left-0.5 top-0.5 ${
                          selectedRule.enabled ? 'translate-x-5' : 'translate-x-0'
                        }`}></div>
                      </div>
                      <span className="ml-2 text-sm font-medium text-gray-700">
                        {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </label>
                  </div>
                  
                  <div className="flex mb-4">
                    <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                      selectedRule.level === 'high' ? 'bg-red-100 text-red-800' :
                      selectedRule.level === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-blue-100 text-blue-800'
                    }`}>
                      {selectedRule.level || 'low'}
                    </span>
                    <span className="ml-2 text-gray-500 text-sm">ID: {selectedRule.id}</span>
                  </div>
                  
                  {selectedRule.description && (
                    <div className="mb-4">
                      <h3 className="text-md font-semibold mb-2">Description</h3>
                      <p className="text-gray-700">{selectedRule.description}</p>
                    </div>
                  )}
                  
                  {selectedRule.author && (
                    <div className="mb-4">
                      <h3 className="text-md font-semibold mb-2">Author</h3>
                      <p className="text-gray-700">{selectedRule.author}</p>
                    </div>
                  )}
                  
                  {selectedRule.tags && selectedRule.tags.length > 0 && (
                    <div className="mb-4">
                      <h3 className="text-md font-semibold mb-2">Tags</h3>
                      <div className="flex flex-wrap gap-2">
                        {selectedRule.tags.map(tag => (
                          <span key={tag} className="px-2 py-1 bg-gray-100 rounded text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {selectedRule.yaml && (
                    <div className="mb-4">
                      <h3 className="text-md font-semibold mb-2">Rule Content</h3>
                      <div className="bg-gray-50 p-3 rounded font-mono text-sm overflow-auto max-h-80">
                        <pre className="text-left">
                          {selectedRule.yaml}
                        </pre>
                      </div>
                    </div>
                  )}
                  
                  {selectedRule.falsepositives && (
                    <div className="mb-4">
                      <h3 className="text-md font-semibold mb-2">False Positives</h3>
                      <p className="text-gray-700">{selectedRule.falsepositives}</p>
                    </div>
                  )}
                  
                  {selectedRule.references && selectedRule.references.length > 0 && (
                    <div className="mb-4">
                      <h3 className="text-md font-semibold mb-2">References</h3>
                      <ul className="list-disc ml-5">
                        {selectedRule.references.map((ref, index) => (
                          <li key={index}>
                            <a 
                              href={ref} 
                              target="_blank" 
                              rel="noopener noreferrer" 
                              className="text-blue-600 hover:underline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {ref}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  
                  <div className="text-gray-500 text-sm mt-6">
                    {selectedRule.date && <div>Created: {selectedRule.date}</div>}
                    {selectedRule.modified && <div>Modified: {selectedRule.modified}</div>}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-full p-8 text-center text-gray-500">
              {!isCollapsed && (
                <div>
                  <p className="text-lg mb-2">No Rule Selected</p>
                  <p className="text-sm">Click on a rule to view its details</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const SigmaMatches = () => {
  const [matches, setMatches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedMatch, setSelectedMatch] = useState(null);
  const [isCollapsed, setIsCollapsed] = useState(true);
  const [windowWidth, setWindowWidth] = useState(window.innerWidth);
  const [sidebarWidth, setSidebarWidth] = useState(null);
  const [isResizing, setIsResizing] = useState(false);
  const [filters, setFilters] = useState({
    status: 'all',
    severity: 'all',
    rule: 'all'
  });
  const [availableRules, setAvailableRules] = useState([]);
  
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
  
  // Fetch matches with filters
  const fetchMatches = useCallback(() => {
    setLoading(true);
    
    // Build query params
    const queryParams = new URLSearchParams();
    if (filters.status !== 'all') queryParams.append('status', filters.status);
    if (filters.severity !== 'all') queryParams.append('severity', filters.severity);
    if (filters.rule !== 'all') queryParams.append('rule', filters.rule);
    
    // Fetch matches
    fetch(`/api/sigma/matches?${queryParams.toString()}`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        // Make sure data is an array
        const matchesArray = Array.isArray(data) ? data : [];
        setMatches(matchesArray);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error fetching matches:', error);
        setError(error.message);
        setLoading(false);
      });
  }, [filters]);
  
  // Fetch available rules for filter dropdown
  useEffect(() => {
    fetch('/api/sigma/rules')
      .then(response => response.json())
      .then(data => {
        const rules = Array.isArray(data) ? data.filter(r => r.enabled) : [];
        setAvailableRules(rules);
      })
      .catch(error => {
        console.error('Error fetching rules:', error);
      });
  }, []);
  
  // Fetch matches initially and when filters change
  useEffect(() => {
    fetchMatches();
  }, [fetchMatches]);

  // Update match status
  const updateMatchStatus = (matchId, newStatus) => {
    fetch(`/api/sigma/matches/${matchId}`, {  
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: newStatus })
    })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        // Update the match in the local state
        setMatches(matches.map(match => 
          match.id === matchId ? { ...match, status: newStatus } : match
        ));
        
        // If this is the selected match, update it too
        if (selectedMatch && selectedMatch.id === matchId) {
          setSelectedMatch({ ...selectedMatch, status: newStatus });
        }
      })
      .catch(error => {
        console.error('Error updating match status:', error);
        alert(`Failed to update match status: ${error.message}`);
      });
  };
  
  // Function to toggle sidebar state
  const toggleSidebar = () => {
    const willExpand = isCollapsed;
    console.log(willExpand ? 'EXPANDING sidebar' : 'COLLAPSING sidebar');
    
    if (willExpand) {
      // If we're expanding, use either the saved width or default
      const expandedWidth = sidebarWidth || getDefaultSidebarWidth();
      const sidebarElement = document.querySelector('.match-sidebar-container');
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
      const sidebarElement = document.querySelector('.match-sidebar-container');
      if (sidebarElement) {
        sidebarElement.style.width = `${newWidth}px`;
      }
    };
    
    // Create mouse up handler
    const handleMouseUp = (upEvent) => {
      console.log('Resize ended');
      setIsResizing(false);
      
      // Capture final width
      const sidebarElement = document.querySelector('.match-sidebar-container');
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
  
  // Match selection handler
  const handleMatchSelect = (match) => {
    setSelectedMatch(match);
    
    if (isCollapsed) {
      console.log('Auto-expanding sidebar for match selection');
      const expandedWidth = sidebarWidth || getDefaultSidebarWidth();
      const sidebarElement = document.querySelector('.match-sidebar-container');
      if (sidebarElement) {
        console.log(`Setting sidebar width to ${expandedWidth}px`);
        sidebarElement.style.width = `${expandedWidth}px`;
      }
      setIsCollapsed(false);
    }
  };
  
  // View process by ID from a match
  const viewProcessDetails = (processId) => {
    // Navigate to the process view with the specific ID
    window.location.href = `/?process_id=${processId}`;
  };
  
  // Track window size
  useEffect(() => {
    const handleResize = () => {
      const newWidth = window.innerWidth;
      setWindowWidth(newWidth);
      
      // If sidebar is expanded and we don't have a manually set width,
      // update the sidebar width based on new window dimensions
      if (!isCollapsed && !sidebarWidth) {
        const sidebarElement = document.querySelector('.match-sidebar-container');
        if (sidebarElement) {
          const newDefaultWidth = getDefaultSidebarWidth();
          sidebarElement.style.width = `${newDefaultWidth}px`;
        }
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isCollapsed, sidebarWidth]);
  
  if (loading) return <div className="flex justify-center items-center h-full">Loading matches...</div>;
  if (error) return <div className="flex justify-center items-center h-full text-red-600">Error: {error}</div>;
  
  // Format event data for display
  const formatEventData = (eventDataJson) => {
    try {
      const eventData = JSON.parse(eventDataJson);
      return eventData;
    } catch (e) {
      return { error: "Could not parse event data" };
    }
  };
  
  // Get severity class
  const getSeverityClass = (severity) => {
    switch(severity) {
      case 'high':
        return 'bg-red-100 text-red-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-blue-100 text-blue-800';
    }
  };
  
  // Get status class
  const getStatusClass = (status) => {
    switch(status) {
      case 'new':
        return 'bg-blue-100 text-blue-800';
      case 'in_progress':
        return 'bg-yellow-100 text-yellow-800';
      case 'resolved':
        return 'bg-green-100 text-green-800';
      case 'false_positive':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };
  
  return (
    <div className="flex h-full relative">
      {/* Main content area */}
      <div className="flex-1 overflow-auto">
        <div className="bg-white shadow rounded-lg overflow-hidden">
          {/* Filters */}
          <div className="px-4 py-3 bg-gray-50 border-b">
            <div className="flex flex-wrap items-center gap-4">
              <h2 className="text-lg font-medium text-gray-700">Sigma Matches</h2>
          
              <button
                onClick={fetchMatches}
                className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm"                
              >
                Refresh
              </button>
                
              {/* Add match count badge */}
              <div className="px-2 py-1 bg-gray-200 rounded-full text-sm font-medium">
                {matches.length} matches found
              </div>
              
              <div className="flex items-center space-x-2">
                <label className="text-sm text-gray-700">Status:</label>
                <select 
                  className="rounded border-gray-300 text-sm"
                  value={filters.status}
                  onChange={(e) => setFilters({...filters, status: e.target.value})}
                >
                  <option value="all">All</option>
                  <option value="new">New</option>
                  <option value="in_progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>
              
              <div className="flex items-center space-x-2">
                <label className="text-sm text-gray-700">Severity:</label>
                <select 
                  className="rounded border-gray-300 text-sm"
                  value={filters.severity}
                  onChange={(e) => setFilters({...filters, severity: e.target.value})}
                >
                  <option value="all">All</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              
              <div className="flex items-center space-x-2">
                <label className="text-sm text-gray-700">Rule:</label>
                <select 
                  className="rounded border-gray-300 text-sm"
                  value={filters.rule}
                  onChange={(e) => setFilters({...filters, rule: e.target.value})}
                >
                  <option value="all">All Rules</option>
                  {availableRules.map(rule => (
                    <option key={rule.id} value={rule.id}>{rule.title}</option>
                  ))}
                </select>
              </div>              
            </div>
          </div>
          
          {/* Matches table */}
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Rule</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Process</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Command</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {matches.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-4 text-center text-gray-500">
                    No matches found with the current filters.
                  </td>
                </tr>
              ) : (
                matches.map(match => (
                  <tr 
                    key={match.id} 
                    className={`hover:bg-gray-50 cursor-pointer ${
                      selectedMatch && selectedMatch.id === match.id ? 'bg-blue-50' : ''
                    }`}
                    onClick={() => handleMatchSelect(match)}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(match.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{match.rule_name}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {match.process_name || match.process_id || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500 truncate max-w-xs">
                      {match.command_line || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getSeverityClass(match.severity)}`}>
                        {match.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusClass(match.status)}`}>
                        {match.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
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
        className="match-sidebar-container bg-white border-l shadow-lg flex-shrink-0 flex flex-col h-full z-50"
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
            {isCollapsed ? (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" 
                   stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 18l-6-6 6-6" />
              </svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" 
                   stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 18l6-6-6-6" />
              </svg>
            )}
          </button>
        </div>
        
        {/* Match Details */}
        <div className="flex-1 overflow-y-auto">
          {selectedMatch ? (
            <div className={isCollapsed ? "p-2 text-center" : "p-6 space-y-4"}>
              {isCollapsed ? (
                <div className="font-mono text-sm truncate">{selectedMatch.id}</div>
              ) : (
                <div>
                  <div className="flex justify-between items-center mb-4">
                    <h2 className="text-xl font-bold">{selectedMatch.rule_name}</h2>
                    <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityClass(selectedMatch.severity)}`}>
                      {selectedMatch.severity}
                    </span>
                  </div>
                  
                  <div className="mb-6">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                    <select 
                      className="rounded border-gray-300 w-full"
                      value={selectedMatch.status}
                      onChange={(e) => updateMatchStatus(selectedMatch.id, e.target.value)}
                    >
                      <option value="new">New</option>
                      <option value="in_progress">In Progress</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>
                  
                  <div className="mb-4">
                    <h3 className="text-sm font-medium text-gray-700 mb-1">Time</h3>
                    <p className="text-sm text-gray-900">
                      {new Date(selectedMatch.timestamp).toLocaleString()}
                    </p>
                  </div>
                  
                  <div className="mb-4">
                    <h3 className="text-sm font-medium text-gray-700 mb-1">Rule ID</h3>
                    <p className="text-sm font-mono">{selectedMatch.rule_id}</p>
                  </div>
                  
                  <div className="mb-4">
                    <h3 className="text-sm font-medium text-gray-700 mb-1">Process</h3>
                    <div className="flex items-center">
                      <span className="text-sm font-mono mr-2">{selectedMatch.process_name || selectedMatch.process_id || '-'}</span>
                      <button 
                        className="text-xs text-blue-600 hover:underline"
                        onClick={() => viewProcessDetails(selectedMatch.event_id)}
                      >
                        View Process
                      </button>
                    </div>
                  </div>
                  
                  {selectedMatch.command_line && (
                    <div className="mb-4">
                      <h3 className="text-sm font-medium text-gray-700 mb-1">Command Line</h3>
                      <div className="bg-gray-50 p-2 rounded font-mono text-sm overflow-x-auto">
                        {selectedMatch.command_line}
                      </div>
                    </div>
                  )}
                  
                  {selectedMatch.parent_process_name && (
                    <div className="mb-4">
                      <h3 className="text-sm font-medium text-gray-700 mb-1">Parent Process</h3>
                      <p className="text-sm font-mono">{selectedMatch.parent_process_name}</p>
                    </div>
                  )}
                  
                  {selectedMatch.parent_command_line && (
                    <div className="mb-4">
                      <h3 className="text-sm font-medium text-gray-700 mb-1">Parent Command Line</h3>
                      <div className="bg-gray-50 p-2 rounded font-mono text-sm overflow-x-auto">
                        {selectedMatch.parent_command_line}
                      </div>
                    </div>
                  )}
                  
                  {selectedMatch.username && (
                    <div className="mb-4">
                      <h3 className="text-sm font-medium text-gray-700 mb-1">Username</h3>
                      <p className="text-sm">{selectedMatch.username}</p>
                    </div>
                  )}
                  
                  {selectedMatch.match_details && selectedMatch.match_details.length > 0 && (
                    <div className="mb-4">
                      <h3 className="text-sm font-medium text-gray-700 mb-1">Match Details</h3>
                      <ul className="list-disc pl-5 text-sm">
                        {selectedMatch.match_details.map((detail, index) => (
                          <li key={index}>{detail}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  
                  {selectedMatch.event_data && (
                    <div className="mb-4">
                      <h3 className="text-sm font-medium text-gray-700 mb-1">Event Data</h3>
                      <div className="bg-gray-50 p-2 rounded font-mono text-sm overflow-x-auto max-h-60 overflow-y-auto">
                        <pre>{JSON.stringify(formatEventData(selectedMatch.event_data), null, 2)}</pre>
                      </div>
                    </div>
                  )}
                  
                  <div className="text-xs text-gray-500 mt-4">
                    Match ID: {selectedMatch.id}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-full p-8 text-center text-gray-500">
              {!isCollapsed && (
                <div>
                  <p className="text-lg mb-2">No Match Selected</p>
                  <p className="text-sm">Click on a match to view its details</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const App = () => {
  const [activeSection, setActiveSection] = useState('processes');
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [processes, setProcesses] = useState([]);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
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
  
  const getUrlParam = (param) => {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(param);
  };
  
  const fetchProcesses = async () => {
    try {
      const processId = getUrlParam('process_id');
      
      // URL to fetch processes, with or without ID parameter
      const url = processId 
        ? `/api/processes?id=${processId}`
        : '/api/processes';
        
      const response = await fetch(url);
      const data = await response.json();
      
      if (processId) {
        // If we have a specific process_id, the API returns an object with
        // processes array and selectedId
        setProcesses(data.processes);
        
        // Find the selected process and set it
        const selected = data.processes.find(p => p.id === parseInt(data.selectedId));
        if (selected) {
          handleProcessSelect(selected);
        }
      } else {
        // Default case - just set processes
        setProcesses(data);
      }
      
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };
  
  // Fetch process data
  useEffect(() => {
    // Only fetch if we're on the processes tab
    if (activeSection === 'processes') {
      fetchProcesses();
      if (autoRefresh) {
        const interval = setInterval(fetchProcesses, 5000);
        return () => clearInterval(interval);
      }
    }
  }, [activeSection, autoRefresh]);
  
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
  
  // Render the appropriate content based on active section
  const renderContent = () => {
    switch(activeSection) {
      case 'processes':
        return loading ? (
          <div className="text-center py-12">Loading...</div>
        ) : error ? (
          <div className="text-center py-12 text-red-600">{error}</div>
        ) : (
          <ProcessList 
            processes={processes} 
            onSelectProcess={handleProcessSelect} 
          />
        );
      case 'network':
        return <NetworkConnections />;
      case 'files':
        return <div className="p-12 text-center text-gray-500">File access monitoring coming soon</div>;
      case 'rules':
        return <SigmaRules />;
      case 'matches':
        return <SigmaMatches />;
      default:
        return <div className="p-12 text-center text-gray-500">Select a section</div>;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex overflow-hidden relative">  
      {/* Left Navigation */}
      <LeftNavigation 
        activeSection={activeSection} 
        onChangeSection={setActiveSection}
        collapsed={navCollapsed}
        onToggleCollapse={() => setNavCollapsed(!navCollapsed)}
      />
    
      {/* Main content area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden"> 
        <nav className="bg-white shadow-sm flex-shrink-0"> 
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex items-center">
                <h1 className="text-xl font-bold text-gray-900 capitalize">
                  {activeSection}
                </h1>
              </div>
              <div className="flex items-center">
                {activeSection === 'processes' && (
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={autoRefresh}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-600">Auto-refresh</span>
                  </label>
                )}
              </div>
            </div>
          </div>
        </nav>

        <main className="flex-1 overflow-auto p-4">
          {renderContent()}
        </main>
      </div>
        
      {/* Process Details Sidebar - only show when on processes page */}
      {activeSection === 'processes' && (
        <div>
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
      )}
    </div>
  );
};

ReactDOM.render(React.createElement(App), document.getElementById('root'));
