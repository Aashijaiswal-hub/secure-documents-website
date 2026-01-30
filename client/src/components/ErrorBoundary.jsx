import React from 'react';
import { Button } from "@/components/ui/button";
import { BiErrorCircle } from "react-icons/bi";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught error:", error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/dashboard';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-white rounded-xl shadow-lg border border-slate-200 p-8 text-center">
            <div className="flex justify-center mb-6">
                <div className="p-4 bg-red-50 rounded-full">
                    <BiErrorCircle className="h-12 w-12 text-red-600" />
                </div>
            </div>
            
            <h1 className="text-2xl font-bold text-slate-900 mb-2">Something went wrong</h1>
            <p className="text-slate-500 mb-6 text-sm">
              We encountered an unexpected error. Our team has been notified.
            </p>

            <div className="p-4 bg-slate-100 rounded-lg mb-6 text-left overflow-auto max-h-32">
                <p className="font-mono text-xs text-slate-600 break-words">
                    {this.state.error?.toString()}
                </p>
            </div>

            <div className="flex gap-3 justify-center">
                <Button variant="outline" onClick={this.handleReload}>
                    Reload Page
                </Button>
                <Button onClick={this.handleGoHome}>
                    Go to Dashboard
                </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children; 
  }
}

export default ErrorBoundary;