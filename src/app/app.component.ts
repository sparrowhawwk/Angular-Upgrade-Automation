import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { InputTextModule } from 'primeng/inputtext';
import { ToastModule } from 'primeng/toast';
import { MessageService } from 'primeng/api';
import { ToolbarModule } from 'primeng/toolbar';
import { BadgeModule } from 'primeng/badge';
import { AvatarModule } from 'primeng/avatar';
import { DialogModule } from 'primeng/dialog';
import { ProgressBarModule } from 'primeng/progressbar';

interface FeatureItem {
  id: string;
  name: string;
  category: string;
  status: 'operational' | 'in-progress' | 'verified';
  version: string;
  rating: number;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    ButtonModule,
    CardModule,
    TableModule,
    TagModule,
    InputTextModule,
    ToastModule,
    ToolbarModule,
    BadgeModule,
    AvatarModule,
    DialogModule,
    ProgressBarModule,
  ],
  providers: [MessageService],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = signal('Angular 18 & PrimeNG 18');
  counter = signal(18);
  isDialogVisible = signal(false);
  filterSearch = signal('');

  features = signal<FeatureItem[]>([
    { id: 'FEAT-101', name: 'Angular Signals & Fine-grained Reactivity', category: 'Core Framework', status: 'operational', version: 'v18.2.0', rating: 98 },
    { id: 'FEAT-102', name: 'PrimeNG Styled Mode & Aura Theme', category: 'UI Components', status: 'operational', version: 'v18.0.2', rating: 99 },
    { id: 'FEAT-103', name: 'Standalone Component Architecture', category: 'Architecture', status: 'verified', version: 'v18.2.0', rating: 96 },
    { id: 'FEAT-104', name: 'Zoneless-ready Event Coalescing', category: 'Performance', status: 'in-progress', version: 'v18.2.0', rating: 92 },
    { id: 'FEAT-105', name: 'PrimeIcons & Vector Glyph Set', category: 'Assets', status: 'verified', version: 'v8.0.2', rating: 95 }
  ]);

  constructor(private messageService: MessageService) {}

  incrementCounter() {
    this.counter.update(c => c + 1);
    this.messageService.add({
      severity: 'success',
      summary: 'Signal Updated',
      detail: `Counter updated to ${this.counter()} using Angular 18 signals!`
    });
  }

  showDialog() {
    this.isDialogVisible.set(true);
  }

  hideDialog() {
    this.isDialogVisible.set(false);
  }

  getSeverity(status: string): 'success' | 'info' | 'warn' | 'danger' | 'secondary' {
    switch (status) {
      case 'operational':
        return 'success';
      case 'verified':
        return 'info';
      case 'in-progress':
        return 'warn';
      default:
        return 'secondary';
    }
  }

  notifyQuick(severity: 'info' | 'warn' | 'success', summary: string, detail: string) {
    this.messageService.add({ severity, summary, detail });
  }
}

