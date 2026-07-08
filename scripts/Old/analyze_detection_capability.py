#!/usr/bin/env python3
"""
Analysis script for vulnerability detection capability assessment
"""

import json
import pandas as pd
import re
from collections import Counter, defaultdict
import glob
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

class DetectionAnalyzer:
    def __init__(self, results_file=None):
        if results_file is None:
            # Find most recent results file
            result_files = glob.glob("results/vulnerability_test_results_*.json")
            if not result_files:
                raise FileNotFoundError("No results files found. Run test_vulnerability_detection.py first!")
            results_file = max(result_files)
        
        print(f"📊 Loading results from: {results_file}")
        
        with open(results_file, 'r', encoding='utf-8') as f:
            self.results = json.load(f)
        
        self.successful_results = [r for r in self.results if r['success']]
        print(f"📈 Loaded {len(self.results)} total results ({len(self.successful_results)} successful)")
    
    def analyze_vulnerability_detection(self):
        """Analyze vulnerability detection capabilities"""
        print("\n🔍 Analyzing vulnerability detection capabilities...")
        
        # Define vulnerability keywords for different categories
        vulnerability_patterns = {
            'buffer_overflow': [
                'buffer overflow', 'buffer overrun', 'stack overflow', 'heap overflow',
                'overflow', 'overrun', 'bounds check', 'boundary'
            ],
            'input_validation': [
                'input validation', 'sanitization', 'validation', 'untrusted input',
                'user input', 'parameter validation', 'input check'
            ],
            'memory_corruption': [
                'memory corruption', 'use after free', 'double free', 'memory leak',
                'dangling pointer', 'null pointer', 'memory safety'
            ],
            'injection': [
                'injection', 'sql injection', 'command injection', 'code injection',
                'script injection', 'ldap injection'
            ],
            'denial_service': [
                'denial of service', 'dos', 'resource exhaustion', 'infinite loop',
                'crash', 'hang', 'deadlock'
            ],
            'execution': [
                'code execution', 'arbitrary code', 'remote execution', 'privilege escalation',
                'execute', 'run code', 'command execution'
            ],
            'race_condition': [
                'race condition', 'concurrent', 'thread safety', 'atomic operation',
                'synchronization', 'mutex', 'lock'
            ],
            'cryptographic': [
                'cryptographic', 'encryption', 'hash', 'random', 'crypto',
                'key management', 'certificate'
            ]
        }
        
        # Security-related keywords (general)
        security_keywords = [
            'vulnerability', 'security', 'risk', 'exploit', 'attack', 'malicious',
            'unsafe', 'insecure', 'threat', 'breach', 'compromise'
        ]
        
        analysis_results = defaultdict(lambda: defaultdict(dict))
        
        # Analyze each model's performance
        for model in set(r['model'] for r in self.successful_results):
            model_results = [r for r in self.successful_results if r['model'] == model]
            
            analysis_results[model]['total_tests'] = len(model_results)
            analysis_results[model]['detection_stats'] = {}
            
            # General security awareness
            security_mentions = 0
            vulnerability_detections = 0
            correct_classifications = 0
            
            category_detections = defaultdict(int)
            category_totals = defaultdict(int)
            
            for result in model_results:
                response_lower = result['response'].lower()
                expected_vuln = result['expected_vuln_type'].lower()
                
                # Count general security awareness
                if any(keyword in response_lower for keyword in security_keywords):
                    security_mentions += 1
                
                # Count vulnerability pattern detections
                vuln_detected = False
                for category, patterns in vulnerability_patterns.items():
                    category_totals[category] += 1
                    
                    # Check if expected vulnerability matches this category
                    expected_match = any(pattern in expected_vuln for pattern in patterns)
                    
                    # Check if response mentions this category
                    response_match = any(pattern in response_lower for pattern in patterns)
                    
                    if response_match:
                        category_detections[category] += 1
                        vuln_detected = True
                        
                        # Check if it's a correct classification
                        if expected_match:
                            correct_classifications += 1
                
                if vuln_detected:
                    vulnerability_detections += 1
            
            # Store results
            analysis_results[model]['detection_stats'] = {
                'security_awareness_rate': (security_mentions / len(model_results)) * 100,
                'vulnerability_detection_rate': (vulnerability_detections / len(model_results)) * 100,
                'classification_accuracy': (correct_classifications / len(model_results)) * 100,
                'category_performance': {
                    cat: (detections / category_totals[cat]) * 100 if category_totals[cat] > 0 else 0
                    for cat, detections in category_detections.items()
                }
            }
        
        return dict(analysis_results)
    
    def analyze_response_quality(self):
        """Analyze the quality and depth of responses"""
        print("\n📝 Analyzing response quality...")
        
        quality_metrics = {}
        
        for model in set(r['model'] for r in self.successful_results):
            model_results = [r for r in self.successful_results if r['model'] == model]
            
            response_lengths = [len(r['response']) for r in model_results]
            response_times = [r['response_time'] for r in model_results]
            
            # Analyze response structure
            structured_responses = 0
            detailed_responses = 0
            actionable_responses = 0
            
            for result in model_results:
                response = result['response']
                
                # Check for structured response (numbered lists, bullets, headers)
                if re.search(r'(\d+\.|•|\*|-|\n#+)', response):
                    structured_responses += 1
                
                # Check for detailed response (longer, technical terms)
                tech_terms = ['function', 'variable', 'pointer', 'memory', 'buffer', 'array']
                if len(response) > 200 and any(term in response.lower() for term in tech_terms):
                    detailed_responses += 1
                
                # Check for actionable advice
                action_words = ['recommend', 'should', 'implement', 'fix', 'patch', 'validate']
                if any(word in response.lower() for word in action_words):
                    actionable_responses += 1
            
            quality_metrics[model] = {
                'avg_response_length': sum(response_lengths) / len(response_lengths),
                'avg_response_time': sum(response_times) / len(response_times),
                'structured_response_rate': (structured_responses / len(model_results)) * 100,
                'detailed_response_rate': (detailed_responses / len(model_results)) * 100,
                'actionable_response_rate': (actionable_responses / len(model_results)) * 100
            }
        
        return quality_metrics
    
    def compare_model_sizes(self):
        """Compare performance between different model sizes"""
        print("\n⚖️ Comparing model sizes...")
        
        model_groups = {
            '1.5B': [m for m in set(r['model'] for r in self.results) if '1.5b' in m],
            '7B': [m for m in set(r['model'] for r in self.results) if '7b' in m]
        }
        
        size_comparison = {}
        
        for size, models in model_groups.items():
            if not models:
                continue
                
            size_results = [r for r in self.successful_results if r['model'] in models]
            
            if size_results:
                # Calculate aggregate metrics
                security_mentions = sum(1 for r in size_results 
                                      if any(keyword in r['response'].lower() 
                                            for keyword in ['vulnerability', 'security', 'risk']))
                
                avg_response_time = sum(r['response_time'] for r in size_results) / len(size_results)
                avg_response_length = sum(len(r['response']) for r in size_results) / len(size_results)
                
                size_comparison[size] = {
                    'models': models,
                    'total_tests': len(size_results),
                    'security_awareness_rate': (security_mentions / len(size_results)) * 100,
                    'avg_response_time': avg_response_time,
                    'avg_response_length': avg_response_length,
                    'performance_efficiency': (security_mentions / len(size_results)) / avg_response_time * 100
                }
        
        return size_comparison
    
    def generate_comprehensive_report(self):
        """Generate comprehensive analysis report"""
        print("\n📊 Generating comprehensive report...")
        
        # Run all analyses
        detection_analysis = self.analyze_vulnerability_detection()
        quality_analysis = self.analyze_response_quality()
        size_comparison = self.compare_model_sizes()
        
        # Create report
        report = {
            'metadata': {
                'analysis_timestamp': datetime.now().isoformat(),
                'total_results': len(self.results),
                'successful_results': len(self.successful_results),
                'models_tested': list(set(r['model'] for r in self.results))
            },
            'detection_analysis': detection_analysis,
            'quality_analysis': quality_analysis,
            'size_comparison': size_comparison
        }
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"results/comprehensive_analysis_{timestamp}.json"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Generate human-readable summary
        self.print_report_summary(report)
        
        print(f"\n💾 Full report saved: {report_filename}")
        
        return report
    
    def print_report_summary(self, report):
        """Print human-readable report summary"""
        print("\n" + "="*60)
        print("🎯 VULNERABILITY DETECTION ANALYSIS REPORT")
        print("="*60)
        
        # Overall stats
        metadata = report['metadata']
        print(f"\n📊 OVERVIEW:")
        print(f"   Total tests: {metadata['total_results']}")
        print(f"   Successful tests: {metadata['successful_results']}")
        print(f"   Success rate: {(metadata['successful_results']/metadata['total_results'])*100:.1f}%")
        print(f"   Models tested: {len(metadata['models_tested'])}")
        
        # Model performance
        print(f"\n🤖 MODEL PERFORMANCE:")
        detection_data = report['detection_analysis']
        quality_data = report['quality_analysis']
        
        for model in metadata['models_tested']:
            if model in detection_data and model in quality_data:
                det_stats = detection_data[model]['detection_stats']
                qual_stats = quality_data[model]
                
                print(f"\n   {model}:")
                print(f"      Security awareness: {det_stats['security_awareness_rate']:.1f}%")
                print(f"      Vulnerability detection: {det_stats['vulnerability_detection_rate']:.1f}%")
                print(f"      Classification accuracy: {det_stats['classification_accuracy']:.1f}%")
                print(f"      Avg response time: {qual_stats['avg_response_time']:.1f}s")
                print(f"      Structured responses: {qual_stats['structured_response_rate']:.1f}%")
        
        # Size comparison
        if 'size_comparison' in report and report['size_comparison']:
            print(f"\n📏 SIZE COMPARISON:")
            for size, data in report['size_comparison'].items():
                print(f"\n   {size} Models:")
                print(f"      Models: {', '.join(data['models'])}")
                print(f"      Security awareness: {data['security_awareness_rate']:.1f}%")
                print(f"      Avg response time: {data['avg_response_time']:.1f}s")
                print(f"      Performance efficiency: {data['performance_efficiency']:.2f}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        if report['size_comparison']:
            sizes = list(report['size_comparison'].keys())
            if len(sizes) >= 2:
                size_1, size_2 = sizes, sizes
                eff_1 = report['size_comparison'][size_1]['performance_efficiency']
                eff_2 = report['size_comparison'][size_2]['performance_efficiency']
                
                if eff_1 > eff_2:
                    print(f"   🏆 {size_1} models show better performance efficiency")
                else:
                    print(f"   🏆 {size_2} models show better performance efficiency")
        
        # Best performing model
        best_model = max(detection_data.keys(), 
                        key=lambda m: detection_data[m]['detection_stats']['vulnerability_detection_rate'])
        print(f"   🥇 Best detection rate: {best_model}")
        
        fastest_model = min(quality_data.keys(), 
                          key=lambda m: quality_data[m]['avg_response_time'])
        print(f"   ⚡ Fastest responses: {fastest_model}")

def main():
    print("🚀 Starting vulnerability detection analysis...")
    
    try:
        analyzer = DetectionAnalyzer()
        report = analyzer.generate_comprehensive_report()
        
        print("\n✅ Analysis completed successfully!")
        print("\n📋 Check the results/ directory for detailed reports")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")

if __name__ == "__main__":
    main()
