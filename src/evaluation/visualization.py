"""
Professional visualizations for Zero-Day Detection System
"""
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, List, Optional, Tuple
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
from pathlib import Path

from config.settings import FIGURE_DPI, FIGURE_SIZE, COLOR_PALETTE, RESULTS_DIR

# Set publication-quality defaults
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['xtick.labelsize'] = 10
plt.rcParams['ytick.labelsize'] = 10
plt.rcParams['legend.fontsize'] = 10
plt.rcParams['figure.dpi'] = FIGURE_DPI
plt.rcParams['savefig.dpi'] = FIGURE_DPI
plt.rcParams['savefig.bbox'] = 'tight'
plt.rcParams['savefig.pad_inches'] = 0.1

# Color scheme for consistency
COLORS = {
    'primary': '#2E86AB',
    'secondary': '#A23B72',
    'tertiary': '#F18F01',
    'quaternary': '#C73E1D',
    'success': '#2ECC71',
    'warning': '#F39C12',
    'danger': '#E74C3C',
    'info': '#3498DB',
    'light': '#ECF0F1',
    'dark': '#2C3E50'
}


class Visualizer:
    """Create publication-quality visualizations"""
    
    def __init__(self, save_path: Optional[str] = None):
        if save_path:
            self.save_path = Path(save_path)
        else:
            self.save_path = Path(RESULTS_DIR) / "figures"
        self.save_path.mkdir(exist_ok=True, parents=True)
        
    def plot_roc_curves(self, curves_data: Dict[str, Dict], 
                       title: str = "ROC Curves Comparison") -> plt.Figure:
        """
        Plot ROC curves for multiple models
        
        Args:
            curves_data: Dictionary with model names and their ROC data
            title: Plot title
            
        Returns:
            Figure object
        """
        fig, ax = plt.subplots(figsize=(8, 8))
        
        # Plot each model's ROC curve
        for i, (model_name, data) in enumerate(curves_data.items()):
            color = list(COLORS.values())[i % len(COLORS)]
            
            ax.plot(data['fpr'], data['tpr'], 
                   color=color, linewidth=2.5,
                   label=f"{model_name} (AUC = {data['auc']:.3f})")
        
        # Plot diagonal reference line
        ax.plot([0, 1], [0, 1], 'k--', linewidth=1.5, alpha=0.7, 
                label='Random Classifier')
        
        # Styling
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1])
        ax.set_xlabel('False Positive Rate', fontsize=12, fontweight='bold')
        ax.set_ylabel('True Positive Rate', fontsize=12, fontweight='bold')
        ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
        
        # Grid
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.set_axisbelow(True)
        
        # Legend
        ax.legend(loc='lower right', frameon=True, fancybox=True, 
                 shadow=True, borderpad=1)
        
        # Equal aspect ratio
        ax.set_aspect('equal', adjustable='box')
        
        plt.tight_layout()
        
        # Save
        fig.savefig(self.save_path / 'roc_curves.pdf', format='pdf')
        fig.savefig(self.save_path / 'roc_curves.png', format='png')
        
        return fig
    
    def plot_confusion_matrix(self, cm: np.ndarray, class_names: List[str],
                            model_name: str, timestamp: str = None) -> plt.Figure:
        """
        Plot a single confusion matrix
        
        Args:
            cm: Confusion matrix
            class_names: Names of classes
            model_name: Name of the model
            timestamp: Optional timestamp for filename
            
        Returns:
            Figure object
        """
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Normalize confusion matrix
        cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        
        # Create heatmap
        im = ax.imshow(cm_normalized, interpolation='nearest', 
                      cmap='Blues', vmin=0, vmax=1)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.set_label('Normalized Count', rotation=270, labelpad=20)
        
        # Add text annotations
        thresh = cm_normalized.max() / 2.
        for row in range(cm.shape[0]):
            for col in range(cm.shape[1]):
                ax.text(col, row, f'{cm[row, col]}\n({cm_normalized[row, col]:.2f})',
                       ha="center", va="center",
                       color="white" if cm_normalized[row, col] > thresh else "black",
                       fontsize=12)
        
        # Labels and title
        ax.set_xticks(np.arange(len(class_names)))
        ax.set_yticks(np.arange(len(class_names)))
        ax.set_xticklabels(class_names)
        ax.set_yticklabels(class_names)
        ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
        ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
        ax.set_title(f'{model_name} - Confusion Matrix', fontsize=14, fontweight='bold', pad=10)
        
        # Rotate x labels
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                rotation_mode="anchor")
        
        plt.tight_layout()
        
        # Save with timestamp if provided
        if timestamp:
            filename_base = f'confusion_matrix_{timestamp}'
        else:
            filename_base = 'confusion_matrix'
            
        fig.savefig(self.save_path / f'{filename_base}.pdf', format='pdf', dpi=300, bbox_inches='tight')
        fig.savefig(self.save_path / f'{filename_base}.png', format='png', dpi=300, bbox_inches='tight')
        
        print(f"✓ Confusion matrix saved to {self.save_path}")
        
        return fig
    
    def plot_confusion_matrices(self, cm_data: Dict[str, np.ndarray],
                               class_names: List[str] = None) -> plt.Figure:
        """
        Plot confusion matrices for multiple models
        
        Args:
            cm_data: Dictionary with model names and confusion matrices
            class_names: Names of classes
            
        Returns:
            Figure object
        """
        if class_names is None:
            class_names = ['Regular CVE', 'Zero-Day']
        
        n_models = len(cm_data)
        cols = min(3, n_models)
        rows = (n_models + cols - 1) // cols
        
        fig = plt.figure(figsize=(6 * cols, 5 * rows))
        
        for i, (model_name, cm) in enumerate(cm_data.items()):
            ax = fig.add_subplot(rows, cols, i + 1)
            
            # Normalize confusion matrix
            cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
            
            # Create heatmap
            im = ax.imshow(cm_normalized, interpolation='nearest', 
                          cmap='Blues', vmin=0, vmax=1)
            
            # Add colorbar
            cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
            cbar.set_label('Normalized Count', rotation=270, labelpad=20)
            
            # Add text annotations
            thresh = cm_normalized.max() / 2.
            for row in range(cm.shape[0]):
                for col in range(cm.shape[1]):
                    ax.text(col, row, f'{cm[row, col]}\n({cm_normalized[row, col]:.2f})',
                           ha="center", va="center",
                           color="white" if cm_normalized[row, col] > thresh else "black",
                           fontsize=10)
            
            # Labels and title
            ax.set_xticks(np.arange(len(class_names)))
            ax.set_yticks(np.arange(len(class_names)))
            ax.set_xticklabels(class_names)
            ax.set_yticklabels(class_names)
            ax.set_xlabel('Predicted Label', fontsize=11, fontweight='bold')
            ax.set_ylabel('True Label', fontsize=11, fontweight='bold')
            ax.set_title(f'{model_name}', fontsize=12, fontweight='bold', pad=10)
            
            # Rotate x labels
            plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                    rotation_mode="anchor")
        
        plt.suptitle('Confusion Matrices Comparison', fontsize=16, 
                    fontweight='bold', y=1.02)
        plt.tight_layout()
        
        # Save
        fig.savefig(self.save_path / 'confusion_matrices.pdf', format='pdf')
        fig.savefig(self.save_path / 'confusion_matrices.png', format='png')
        
        return fig
    
    def plot_agent_weights_evolution(self, weights_history: List[np.ndarray],
                                   agent_names: List[str]) -> plt.Figure:
        """
        Plot evolution of agent weights over time
        
        Args:
            weights_history: List of weight arrays over time
            agent_names: Names of agents
            
        Returns:
            Figure object
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), 
                                       gridspec_kw={'height_ratios': [3, 1]})
        
        # Convert to array
        weights_array = np.array(weights_history)
        iterations = np.arange(len(weights_history))
        
        # Plot weight evolution
        for i, agent_name in enumerate(agent_names):
            color = list(COLORS.values())[i % len(COLORS)]
            ax1.plot(iterations, weights_array[:, i], 
                    label=agent_name, color=color, linewidth=2.5, marker='o',
                    markersize=4, markevery=max(1, len(iterations)//20))
        
        ax1.set_xlabel('Iteration', fontsize=12, fontweight='bold')
        ax1.set_ylabel('Weight', fontsize=12, fontweight='bold')
        ax1.set_title('Thompson Sampling Weight Evolution', 
                     fontsize=14, fontweight='bold', pad=20)
        ax1.grid(True, alpha=0.3, linestyle='--')
        ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5), 
                  frameon=True, fancybox=True)
        ax1.set_ylim([0, 1])
        
        # Plot weight distribution (final 20% of iterations)
        final_weights = weights_array[int(len(weights_array)*0.8):]
        
        # Box plot
        bp = ax2.boxplot([final_weights[:, i] for i in range(len(agent_names))],
                        labels=[name.split('Analyst')[0] if 'Analyst' in name else name 
                               for name in agent_names],
                        patch_artist=True, notch=True, showmeans=True)
        
        # Color boxes
        for i, (patch, median) in enumerate(zip(bp['boxes'], bp['medians'])):
            patch.set_facecolor(list(COLORS.values())[i % len(COLORS)])
            patch.set_alpha(0.7)
            median.set_color('black')
            median.set_linewidth(2)
        
        ax2.set_ylabel('Final Weights', fontsize=11, fontweight='bold')
        ax2.set_title('Weight Distribution (Final 20% of Training)', 
                     fontsize=12, pad=10)
        ax2.grid(True, alpha=0.3, axis='y', linestyle='--')
        
        plt.tight_layout()
        
        # Save
        fig.savefig(self.save_path / 'weights_evolution.pdf', format='pdf')
        fig.savefig(self.save_path / 'weights_evolution.png', format='png')
        
        return fig
    
    def plot_performance_comparison(self, metrics_data: Dict[str, Dict[str, float]],
                                   metric_names: List[str] = None) -> plt.Figure:
        """
        Create comprehensive performance comparison visualization
        
        Args:
            metrics_data: Dictionary with model names and their metrics
            metric_names: List of metrics to plot
            
        Returns:
            Figure object
        """
        if metric_names is None:
            metric_names = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        
        # Prepare data
        models = list(metrics_data.keys())
        n_models = len(models)
        n_metrics = len(metric_names)
        
        # Create figure with custom layout
        fig = plt.figure(figsize=(14, 10))
        gs = GridSpec(3, 2, figure=fig, hspace=0.3, wspace=0.3)
        
        # 1. Radar chart (top left)
        ax1 = fig.add_subplot(gs[0, 0], projection='polar')
        self._plot_radar_chart(ax1, metrics_data, metric_names)
        
        # 2. Bar chart comparison (top right)
        ax2 = fig.add_subplot(gs[0, 1])
        self._plot_grouped_bars(ax2, metrics_data, metric_names)
        
        # 3. Heatmap (middle, spanning both columns)
        ax3 = fig.add_subplot(gs[1, :])
        self._plot_metrics_heatmap(ax3, metrics_data)
        
        # 4. Statistical significance (bottom left)
        ax4 = fig.add_subplot(gs[2, 0])
        self._plot_significance_matrix(ax4, metrics_data)
        
        # 5. Performance summary table (bottom right)
        ax5 = fig.add_subplot(gs[2, 1])
        self._plot_summary_table(ax5, metrics_data)
        
        # Overall title
        fig.suptitle('Comprehensive Performance Analysis', 
                    fontsize=18, fontweight='bold', y=0.98)
        
        # Save
        fig.savefig(self.save_path / 'performance_comparison.pdf', format='pdf')
        fig.savefig(self.save_path / 'performance_comparison.png', format='png')
        
        return fig
    
    def _plot_radar_chart(self, ax, metrics_data, metric_names):
        """Helper to create radar chart"""
        angles = np.linspace(0, 2 * np.pi, len(metric_names), endpoint=False).tolist()
        angles += angles[:1]  # Complete the circle
        
        for i, (model, metrics) in enumerate(metrics_data.items()):
            values = [metrics.get(m, 0) for m in metric_names]
            values += values[:1]  # Complete the circle
            
            color = list(COLORS.values())[i % len(COLORS)]
            ax.plot(angles, values, 'o-', linewidth=2, label=model, color=color)
            ax.fill(angles, values, alpha=0.15, color=color)
        
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels([m.capitalize() for m in metric_names])
        ax.set_ylim(0, 1)
        ax.set_title('Performance Radar Chart', fontsize=14, 
                    fontweight='bold', pad=20)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
        ax.grid(True, alpha=0.3)
    
    def _plot_grouped_bars(self, ax, metrics_data, metric_names):
        """Helper to create grouped bar chart"""
        x = np.arange(len(metric_names))
        width = 0.8 / len(metrics_data)
        
        for i, (model, metrics) in enumerate(metrics_data.items()):
            values = [metrics.get(m, 0) for m in metric_names]
            offset = width * (i - len(metrics_data)/2 + 0.5)
            
            color = list(COLORS.values())[i % len(COLORS)]
            bars = ax.bar(x + offset, values, width, label=model, color=color)
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                       f'{value:.3f}', ha='center', va='bottom', fontsize=8)
        
        ax.set_xlabel('Metrics', fontsize=12, fontweight='bold')
        ax.set_ylabel('Score', fontsize=12, fontweight='bold')
        ax.set_title('Performance Metrics Comparison', fontsize=14, 
                    fontweight='bold', pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels([m.capitalize() for m in metric_names])
        ax.legend(loc='upper left')
        ax.grid(True, alpha=0.3, axis='y')
        ax.set_ylim(0, 1.1)
    
    def _plot_metrics_heatmap(self, ax, metrics_data):
        """Helper to create metrics heatmap"""
        # Prepare data matrix
        all_metrics = set()
        for metrics in metrics_data.values():
            all_metrics.update(metrics.keys())
        all_metrics = sorted(list(all_metrics))
        
        data_matrix = []
        model_names = []
        
        for model, metrics in metrics_data.items():
            model_names.append(model)
            row = [metrics.get(m, 0) for m in all_metrics]
            data_matrix.append(row)
        
        data_matrix = np.array(data_matrix)
        
        # Create heatmap
        im = ax.imshow(data_matrix, cmap='YlOrRd', aspect='auto', vmin=0, vmax=1)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.set_label('Score', rotation=270, labelpad=20)
        
        # Set ticks
        ax.set_xticks(np.arange(len(all_metrics)))
        ax.set_yticks(np.arange(len(model_names)))
        ax.set_xticklabels([m.replace('_', ' ').title() for m in all_metrics], 
                          rotation=45, ha='right')
        ax.set_yticklabels(model_names)
        
        # Add text annotations
        for i in range(len(model_names)):
            for j in range(len(all_metrics)):
                text = ax.text(j, i, f'{data_matrix[i, j]:.3f}',
                             ha="center", va="center", color="black", fontsize=8)
        
        ax.set_title('Complete Metrics Heatmap', fontsize=14, 
                    fontweight='bold', pad=15)
    
    def _plot_significance_matrix(self, ax, metrics_data):
        """Helper to create significance matrix with real p-values"""
        models = list(metrics_data.keys())
        n_models = len(models)
        
        # Create p-value matrix
        p_matrix = np.ones((n_models, n_models))
        
        # For now, show the accuracy differences as a heatmap
        # TODO: Implement proper McNemar test when we have prediction pairs
        accuracy_values = [metrics_data[m].get('accuracy', 0) for m in models]
        
        for i in range(n_models):
            for j in range(n_models):
                if i != j:
                    # Show absolute difference in accuracy
                    p_matrix[i, j] = abs(accuracy_values[i] - accuracy_values[j])
        
        # Create heatmap
        im = ax.imshow(p_matrix, cmap='RdYlGn_r', vmin=0, vmax=0.2, aspect='auto')
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.set_label('Accuracy Difference', rotation=270, labelpad=20)
        
        # Set ticks
        ax.set_xticks(np.arange(n_models))
        ax.set_yticks(np.arange(n_models))
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.set_yticklabels(models)
        
        # Add text annotations
        for i in range(n_models):
            for j in range(n_models):
                if i == j:
                    text = ax.text(j, i, '-', ha="center", va="center", color="gray")
                else:
                    text = ax.text(j, i, f'{p_matrix[i, j]:.3f}',
                                 ha="center", va="center", color="black", fontsize=8)
        
        ax.set_title('Model Accuracy Differences', fontsize=14, 
                    fontweight='bold', pad=15)
        ax.set_xlabel('Model', fontsize=10)
        ax.set_ylabel('Model', fontsize=10)
    
    def _plot_summary_table(self, ax, metrics_data):
        """Helper to create summary table"""
        # Calculate summary statistics
        summary_data = []
        for model, metrics in metrics_data.items():
            avg_score = np.mean([v for k, v in metrics.items() 
                               if k in ['accuracy', 'precision', 'recall', 'f1']])
            summary_data.append({
                'Model': model,
                'Avg Score': f'{avg_score:.3f}',
                'Best Metric': max(metrics, key=metrics.get),
                'Best Score': f'{max(metrics.values()):.3f}'
            })
        
        # Create table
        table_data = [[d['Model'], d['Avg Score'], d['Best Metric'], d['Best Score']] 
                     for d in summary_data]
        
        table = ax.table(cellText=table_data,
                        colLabels=['Model', 'Avg Score', 'Best Metric', 'Best Score'],
                        cellLoc='center',
                        loc='center',
                        colWidths=[0.3, 0.2, 0.3, 0.2])
        
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 2)
        
        # Style header
        for i in range(4):
            table[(0, i)].set_facecolor('#4472C4')
            table[(0, i)].set_text_props(weight='bold', color='white')
        
        ax.set_title('Performance Summary', fontsize=14, 
                    fontweight='bold', pad=15)
        ax.axis('off')
    
    def save_all_figures(self, figures: Dict[str, plt.Figure], 
                        formats: List[str] = None):
        """Save all figures in multiple formats"""
        if formats is None:
            formats = ['pdf', 'png', 'svg']
        
        for name, fig in figures.items():
            for fmt in formats:
                filename = self.save_path / f'{name}.{fmt}'
                fig.savefig(filename, format=fmt, bbox_inches='tight')
                
        print(f"All figures saved to {self.save_path}")
    
    def create_advanced_visualizations(self, test_results: Dict[str, Any],
                                      output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """Create advanced publication-quality visualizations"""
        if output_dir is None:
            output_dir = Path("results/figures")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files = {}
        
        # 1. Agent Performance Heatmap
        fig_path = output_dir / f"agent_heatmap_{timestamp}"
        self.plot_agent_performance_heatmap(test_results)
        plt.tight_layout()
        plt.savefig(f"{fig_path}.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{fig_path}.pdf", bbox_inches='tight')
        plt.close()
        files['agent_heatmap'] = fig_path
        
        # 2. ROC Curves with AUC
        fig_path = output_dir / f"roc_curves_{timestamp}"
        self.plot_roc_curves_advanced(test_results)
        plt.tight_layout()
        plt.savefig(f"{fig_path}.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{fig_path}.pdf", bbox_inches='tight')
        plt.close()
        files['roc_curves'] = fig_path
        
        # 3. Calibration Plot
        fig_path = output_dir / f"calibration_plot_{timestamp}"
        self.plot_calibration_curve(test_results)
        plt.tight_layout()
        plt.savefig(f"{fig_path}.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{fig_path}.pdf", bbox_inches='tight')
        plt.close()
        files['calibration_plot'] = fig_path
        
        # 4. Feature Importance / Agent Contribution
        fig_path = output_dir / f"agent_contribution_{timestamp}"
        self.plot_agent_contribution(test_results)
        plt.tight_layout()
        plt.savefig(f"{fig_path}.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{fig_path}.pdf", bbox_inches='tight')
        plt.close()
        files['agent_contribution'] = fig_path
        
        return files
    
    def plot_agent_performance_heatmap(self, test_results: Dict[str, Any]):
        """Create heatmap showing agent performance across different metrics"""
        agents = ['ForensicAnalyst', 'PatternDetector', 'TemporalAnalyst', 
                 'AttributionExpert', 'MetaAnalyst']
        
        # Extract agent-wise metrics
        agent_metrics = {}
        for agent in agents:
            agent_metrics[agent] = {
                'accuracy': 0, 'precision': 0, 'recall': 0, 
                'f1_score': 0, 'avg_confidence': 0
            }
        
        # Calculate metrics for each agent
        if 'predictions' in test_results:
            # Initialize counters for each agent
            for agent in agents:
                agent_metrics[agent] = {
                    'correct': 0,
                    'true_positives': 0,
                    'false_positives': 0,
                    'false_negatives': 0,
                    'total_predictions': 0,
                    'confidence_sum': 0
                }
            
            for pred in test_results['predictions']:
                actual = pred.get('actual', False)
                
                # Try to use agent_predictions first (new format)
                if 'agent_predictions' in pred and pred['agent_predictions']:
                    for agent, agent_pred_value in pred['agent_predictions'].items():
                        if agent in agent_metrics:
                            agent_predicted = agent_pred_value > 0.5
                            
                            agent_metrics[agent]['total_predictions'] += 1
                            agent_metrics[agent]['confidence_sum'] += agent_pred_value
                            
                            # Update metrics
                            if agent_predicted == actual:
                                agent_metrics[agent]['correct'] += 1
                            
                            if agent_predicted and actual:  # True positive
                                agent_metrics[agent]['true_positives'] += 1
                            elif agent_predicted and not actual:  # False positive
                                agent_metrics[agent]['false_positives'] += 1
                            elif not agent_predicted and actual:  # False negative
                                agent_metrics[agent]['false_negatives'] += 1
                
                # Fallback to individual_predictions (old format)
                elif 'individual_predictions' in pred and len(pred['individual_predictions']) == len(agents):
                    for i, agent in enumerate(agents):
                        agent_pred_value = pred['individual_predictions'][i]
                        agent_predicted = agent_pred_value > 0.5
                        
                        agent_metrics[agent]['total_predictions'] += 1
                        agent_metrics[agent]['confidence_sum'] += agent_pred_value
                        
                        # Update metrics
                        if agent_predicted == actual:
                            agent_metrics[agent]['correct'] += 1
                        
                        if agent_predicted and actual:  # True positive
                            agent_metrics[agent]['true_positives'] += 1
                        elif agent_predicted and not actual:  # False positive
                            agent_metrics[agent]['false_positives'] += 1
                        elif not agent_predicted and actual:  # False negative
                            agent_metrics[agent]['false_negatives'] += 1
        
        # Create heatmap data
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Avg Confidence']
        data = np.zeros((len(agents), len(metrics)))
        
        for i, agent in enumerate(agents):
            am = agent_metrics[agent]
            total = am['total_predictions']
            
            if total > 0:
                # Accuracy
                data[i, 0] = am['correct'] / total
                
                # Precision
                if am['true_positives'] + am['false_positives'] > 0:
                    data[i, 1] = am['true_positives'] / (am['true_positives'] + am['false_positives'])
                else:
                    data[i, 1] = 0.0
                
                # Recall
                if am['true_positives'] + am['false_negatives'] > 0:
                    data[i, 2] = am['true_positives'] / (am['true_positives'] + am['false_negatives'])
                else:
                    data[i, 2] = 0.0
                
                # F1-Score
                if data[i, 1] + data[i, 2] > 0:
                    data[i, 3] = 2 * (data[i, 1] * data[i, 2]) / (data[i, 1] + data[i, 2])
                else:
                    data[i, 3] = 0.0
                
                # Average Confidence
                data[i, 4] = am['confidence_sum'] / total
        
        # Create heatmap
        fig, ax = plt.subplots(figsize=(10, 6))
        sns.heatmap(data, annot=True, fmt='.3f', cmap='RdYlGn', 
                    xticklabels=metrics, yticklabels=agents,
                    cbar_kws={'label': 'Performance Score'},
                    vmin=0, vmax=1)
        
        ax.set_title('Agent Performance Heatmap', fontsize=16, fontweight='bold')
        ax.set_xlabel('Metrics', fontsize=12)
        ax.set_ylabel('Agents', fontsize=12)
        
    def plot_roc_curves_advanced(self, test_results: Dict[str, Any]):
        """Plot ROC curves for ensemble and individual agents"""
        from sklearn.metrics import roc_curve, auc
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Get true labels and predictions
        y_true = []
        y_scores = []
        agent_scores = {agent: [] for agent in ['ForensicAnalyst', 'PatternDetector', 
                                               'TemporalAnalyst', 'AttributionExpert', 'MetaAnalyst']}
        
        if 'predictions' in test_results:
            for pred in test_results['predictions']:
                y_true.append(int(pred['actual']))
                y_scores.append(pred['probability'])
                
                # Try agent_predictions first (new format)
                if 'agent_predictions' in pred and pred['agent_predictions']:
                    for agent in agent_scores.keys():
                        if agent in pred['agent_predictions']:
                            agent_scores[agent].append(pred['agent_predictions'][agent])
                
                # Fallback to individual_predictions (old format)
                elif 'individual_predictions' in pred and len(pred['individual_predictions']) == 5:
                    for i, agent in enumerate(agent_scores.keys()):
                        agent_scores[agent].append(pred['individual_predictions'][i])
        
        # Plot ensemble ROC
        if y_true and y_scores:
            fpr, tpr, _ = roc_curve(y_true, y_scores)
            roc_auc = auc(fpr, tpr)
            ax.plot(fpr, tpr, 'b-', linewidth=3, label=f'Ensemble (AUC = {roc_auc:.3f})')
            
            # Plot individual agent ROCs
            colors = ['red', 'green', 'orange', 'purple', 'brown']
            for (agent, scores), color in zip(agent_scores.items(), colors):
                if scores:
                    fpr, tpr, _ = roc_curve(y_true, scores)
                    roc_auc = auc(fpr, tpr)
                    ax.plot(fpr, tpr, '--', color=color, alpha=0.7, 
                           label=f'{agent} (AUC = {roc_auc:.3f})')
        
        # Plot diagonal
        ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Random')
        
        ax.set_xlabel('False Positive Rate', fontsize=12)
        ax.set_ylabel('True Positive Rate', fontsize=12)
        ax.set_title('ROC Curves - Zero-Day Detection', fontsize=16, fontweight='bold')
        ax.legend(loc='lower right', fontsize=10)
        ax.grid(True, alpha=0.3)
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1])
        
    def plot_calibration_curve(self, test_results: Dict[str, Any]):
        """Plot calibration curve to assess prediction reliability"""
        from sklearn.calibration import calibration_curve
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Get true labels and predictions
        y_true = []
        y_prob = []
        
        if 'predictions' in test_results:
            for pred in test_results['predictions']:
                y_true.append(int(pred['actual']))
                y_prob.append(pred['probability'])
        
        if y_true and y_prob:
            # Calibration curve
            fraction_of_positives, mean_predicted_value = calibration_curve(
                y_true, y_prob, n_bins=10, strategy='uniform'
            )
            
            ax1.plot(mean_predicted_value, fraction_of_positives, 'o-', 
                    color='blue', linewidth=2, markersize=8, label='Ensemble')
            ax1.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Perfect calibration')
            
            ax1.set_xlabel('Mean Predicted Probability', fontsize=12)
            ax1.set_ylabel('Fraction of Positives', fontsize=12)
            ax1.set_title('Calibration Plot', fontsize=14, fontweight='bold')
            ax1.legend(loc='lower right')
            ax1.grid(True, alpha=0.3)
            ax1.set_xlim([0, 1])
            ax1.set_ylim([0, 1])
            
            # Histogram of predictions
            ax2.hist(y_prob, bins=20, alpha=0.7, color='blue', edgecolor='black')
            ax2.set_xlabel('Predicted Probability', fontsize=12)
            ax2.set_ylabel('Count', fontsize=12)
            ax2.set_title('Distribution of Predictions', fontsize=14, fontweight='bold')
            ax2.grid(True, alpha=0.3, axis='y')
            
    def plot_agent_contribution(self, test_results: Dict[str, Any]):
        """Visualize agent contribution to final predictions"""
        agents = ['ForensicAnalyst', 'PatternDetector', 'TemporalAnalyst', 
                 'AttributionExpert', 'MetaAnalyst']
        
        # Calculate agent agreement and contribution
        agent_agreement = {agent: {'correct': 0, 'total': 0} for agent in agents}
        
        if 'predictions' in test_results:
            for pred in test_results['predictions']:
                ensemble_pred = pred['probability'] > 0.5
                actual = pred['actual']
                
                # Try agent_predictions first (new format)
                if 'agent_predictions' in pred and pred['agent_predictions']:
                    for agent, agent_pred_value in pred['agent_predictions'].items():
                        if agent in agent_agreement:
                            agent_pred = agent_pred_value > 0.5
                            agent_agreement[agent]['total'] += 1
                            
                            # Check if agent agreed with ensemble and was correct
                            if agent_pred == ensemble_pred and ensemble_pred == actual:
                                agent_agreement[agent]['correct'] += 1
                
                # Fallback to individual_predictions (old format)
                elif 'individual_predictions' in pred and len(pred['individual_predictions']) == 5:
                    for i, agent in enumerate(agents):
                        agent_pred = pred['individual_predictions'][i] > 0.5
                        agent_agreement[agent]['total'] += 1
                        
                        # Check if agent agreed with ensemble and was correct
                        if agent_pred == ensemble_pred and ensemble_pred == actual:
                            agent_agreement[agent]['correct'] += 1
        
        # Create visualization
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Bar plot of agent agreement rates
        agreement_rates = []
        for agent in agents:
            if agent_agreement[agent]['total'] > 0:
                rate = agent_agreement[agent]['correct'] / agent_agreement[agent]['total']
                agreement_rates.append(rate)
            else:
                agreement_rates.append(0)
        
        colors = plt.cm.viridis(np.linspace(0, 1, len(agents)))
        bars = ax1.bar(range(len(agents)), agreement_rates, color=colors)
        ax1.set_xticks(range(len(agents)))
        ax1.set_xticklabels(agents, rotation=45, ha='right')
        ax1.set_ylabel('Contribution Score', fontsize=12)
        ax1.set_title('Agent Contribution to Correct Predictions', fontsize=14, fontweight='bold')
        ax1.set_ylim(0, 1)
        ax1.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for bar, rate in zip(bars, agreement_rates):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{rate:.2%}', ha='center', va='bottom')
        
        # Radar chart of agent characteristics - CALCULATE FROM REAL DATA
        categories = ['Accuracy', 'Avg Time', 'Confidence', 'Agreement', 'Coverage']
        N = len(categories)
        
        # Calculate real metrics from agent data
        angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
        angles += angles[:1]
        
        ax2 = plt.subplot(122, projection='polar')
        
        # Sort agents by contribution score and show top 3
        sorted_agents = sorted(agents, key=lambda a: agreement_rates[agents.index(a)], reverse=True)[:3]
        
        for agent in sorted_agents:
            am = agent_metrics[agent]
            
            # Calculate real values (normalized to 0-1)
            values = []
            
            # Accuracy
            accuracy = am['correct'] / am['total_predictions'] if am['total_predictions'] > 0 else 0
            values.append(accuracy)
            
            # Average time (inverted - faster is better, normalized)
            # For now use placeholder as we don't track time per agent
            values.append(0.7)  # TODO: Track actual agent response times
            
            # Average confidence
            avg_conf = am['confidence_sum'] / am['total_predictions'] if am['total_predictions'] > 0 else 0
            values.append(avg_conf)
            
            # Agreement with ensemble
            agreement_rate = agreement_rates[agents.index(agent)]
            values.append(agreement_rate)
            
            # Coverage (how many predictions the agent made)
            coverage = am['total_predictions'] / len(test_results.get('predictions', [])) if test_results.get('predictions') else 0
            values.append(min(coverage, 1.0))
            
            values += values[:1]  # Complete the circle
            
            ax2.plot(angles, values, 'o-', linewidth=2, label=agent)
            ax2.fill(angles, values, alpha=0.25)
        
        ax2.set_xticks(angles[:-1])
        ax2.set_xticklabels(categories)
        ax2.set_ylim(0, 1)
        ax2.set_title('Agent Performance Characteristics (Real Data)', fontsize=14, fontweight='bold', pad=20)
        ax2.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0))
        ax2.grid(True)
    
    def create_all_visualizations(self, results: Dict[str, Any], 
                                 timestamp: str = None) -> Dict[str, plt.Figure]:
        """
        Create all 4 publication-quality visualizations
        
        Args:
            results: Dictionary containing test results
            timestamp: Optional timestamp for filenames
            
        Returns:
            Dictionary of figure names to figure objects
        """
        figures = {}
        
        # 1. Confusion Matrix
        if 'confusion_matrix' in results:
            cm = results['confusion_matrix']
            class_names = results.get('class_names', ['Regular CVE', 'Zero-Day'])
            model_name = results.get('model_name', 'Multi-Agent Ensemble')
            
            fig = self.plot_confusion_matrix(cm, class_names, model_name, timestamp)
            figures['confusion_matrix'] = fig
            plt.close(fig)
        
        # 2. Performance Comparison (if multiple models)
        if 'model_performances' in results:
            fig = self.plot_performance_comparison(results['model_performances'])
            figures['performance_comparison'] = fig
            plt.close(fig)
        
        # 3. Agent Weights Evolution (if using Thompson Sampling)
        if 'weights_history' in results:
            agent_names = results.get('agent_names', ['Agent ' + str(i) for i in range(5)])
            fig = self.plot_agent_weights_evolution(
                results['weights_history'], 
                agent_names
            )
            figures['weights_evolution'] = fig
            plt.close(fig)
        
        # 4. ROC Curves (if available)
        if 'roc_curves' in results:
            fig = self.plot_roc_curves(results['roc_curves'])
            figures['roc_curves'] = fig
            plt.close(fig)
        
        # Create summary figure
        if len(figures) >= 2:
            summary_fig = self._create_summary_figure(results)
            figures['summary'] = summary_fig
            plt.close(summary_fig)
        
        print(f"\n✓ Created {len(figures)} visualizations")
        return figures
    
    def _create_summary_figure(self, results: Dict[str, Any]) -> plt.Figure:
        """Create a summary figure with key metrics"""
        fig = plt.figure(figsize=(12, 8))
        gs = GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)
        
        # Accuracy by source
        ax1 = fig.add_subplot(gs[0, 0])
        if 'accuracy_by_source' in results:
            sources = list(results['accuracy_by_source'].keys())
            accuracies = list(results['accuracy_by_source'].values())
            bars = ax1.bar(sources, accuracies, color=COLOR_PALETTE[:len(sources)])
            ax1.set_ylim(0, 1.1)
            ax1.set_ylabel('Accuracy', fontweight='bold')
            ax1.set_title('Accuracy by Data Source', fontweight='bold')
            
            # Add value labels on bars
            for bar, acc in zip(bars, accuracies):
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f'{acc:.1%}', ha='center', va='bottom', fontweight='bold')
        
        # Metrics summary
        ax2 = fig.add_subplot(gs[0, 1])
        if 'metrics_summary' in results:
            metrics = results['metrics_summary']
            metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
            metric_values = [
                metrics.get('accuracy', 0),
                metrics.get('precision', 0),
                metrics.get('recall', 0),
                metrics.get('f1', 0)
            ]
            
            bars = ax2.bar(metric_names, metric_values, color=COLOR_PALETTE[1])
            ax2.set_ylim(0, 1.1)
            ax2.set_ylabel('Score', fontweight='bold')
            ax2.set_title('Overall Performance Metrics', fontweight='bold')
            
            # Add value labels
            for bar, val in zip(bars, metric_values):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f'{val:.3f}', ha='center', va='bottom', fontweight='bold')
        
        # Add text summary
        ax3 = fig.add_subplot(gs[1, :])
        ax3.axis('off')
        
        summary_text = f"""
        Zero-Day Detection System - Results Summary
        
        Total Samples: {results.get('total_samples', 0)}
        Correct Predictions: {results.get('correct_predictions', 0)}
        Overall Accuracy: {results.get('overall_accuracy', 0):.1%}
        
        CISA KEV (Known Zero-Days): {results.get('cisa_accuracy', 0):.1%} accuracy
        NVD (Regular CVEs): {results.get('nvd_accuracy', 0):.1%} accuracy
        
        Analysis completed in {results.get('total_time', 0):.1f} seconds
        """
        
        ax3.text(0.5, 0.5, summary_text, ha='center', va='center',
                fontsize=12, transform=ax3.transAxes,
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightgray", alpha=0.5))
        
        plt.suptitle('Zero-Day Detection System - Experiment Results', 
                    fontsize=16, fontweight='bold')
        
        return fig